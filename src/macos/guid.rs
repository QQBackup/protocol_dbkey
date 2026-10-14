//! macOS 设备 guid：`guid = MD5( machineid-info 的 machine_id[8] ‖ sn )`。
//!
//! 逆向自 macOS `wrapper.node`（见 `../qq_guid_tool/macos`）：
//! * `machine_id` 优先从 `<root>/global/nt_data/msf/machineid-info` **TEA 容器解密**
//!   读出（明文 `be32(8)+mid[8] + be32(len)+sn`）；文件缺失/为空时回退成
//!   `machine_id = 主网卡 MAC(6) + 00 00`。
//! * `sn` 优先取 `/dev/disk0` 序列号，失败回退 `IOPlatformSerialNumber`。
//! * TEA 密钥 = `IOPlatformUUID` 字符串前 16 字节（大端解释）。
//!
//! 容器 / TEA 规格：`P_i = X_i ^ C_(i-1)`、`C_i = E(P_i) ^ P_(i-1)`，明文流
//! `[head][v8 随机][2 随机] + payload + 00*7`，TEA 16 轮 delta `0x9E3779B9` 大端。

use std::path::{Path, PathBuf};

const DELTA: u32 = 0x9E37_79B9;
const BLOCK: usize = 8;

/// 相对数据根路径的候选位置。
const CANDIDATES: [&[&str]; 2] = [
    &["global", "nt_data", "msf", "machineid-info"],
    &["nt_qq", "global", "nt_data", "msf", "machineid-info"],
];

fn key_words(key: &[u8]) -> [u32; 4] {
    let mut k = [0u8; 16];
    let n = key.len().min(16);
    k[..n].copy_from_slice(&key[..n]);
    [
        u32::from_be_bytes(k[0..4].try_into().unwrap()),
        u32::from_be_bytes(k[4..8].try_into().unwrap()),
        u32::from_be_bytes(k[8..12].try_into().unwrap()),
        u32::from_be_bytes(k[12..16].try_into().unwrap()),
    ]
}

/// 加密一个 8 字节块（16 轮，大端）。
pub fn tea_encrypt_block(block: &[u8], key: &[u8]) -> [u8; 8] {
    assert_eq!(block.len(), BLOCK);
    let mut v0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut v1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let [k0, k1, k2, k3] = key_words(key);
    let mut s = DELTA;
    for _ in 0..16 {
        v0 = v0.wrapping_add(
            ((v1 << 4).wrapping_add(k0)) ^ v1.wrapping_add(s) ^ ((v1 >> 5).wrapping_add(k1)),
        );
        v1 = v1.wrapping_add(
            ((v0 << 4).wrapping_add(k2)) ^ v0.wrapping_add(s) ^ ((v0 >> 5).wrapping_add(k3)),
        );
        s = s.wrapping_add(DELTA);
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&v0.to_be_bytes());
    out[4..8].copy_from_slice(&v1.to_be_bytes());
    out
}

/// 解密一个 8 字节块。
pub fn tea_decrypt_block(block: &[u8], key: &[u8]) -> [u8; 8] {
    assert_eq!(block.len(), BLOCK);
    let mut v0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut v1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let [k0, k1, k2, k3] = key_words(key);
    let mut s = DELTA.wrapping_mul(16);
    for _ in 0..16 {
        v1 = v1.wrapping_sub(
            ((v0 << 4).wrapping_add(k2)) ^ v0.wrapping_add(s) ^ ((v0 >> 5).wrapping_add(k3)),
        );
        v0 = v0.wrapping_sub(
            ((v1 << 4).wrapping_add(k0)) ^ v1.wrapping_add(s) ^ ((v1 >> 5).wrapping_add(k1)),
        );
        s = s.wrapping_sub(DELTA);
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&v0.to_be_bytes());
    out[4..8].copy_from_slice(&v1.to_be_bytes());
    out
}

fn xor8(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// 解开 QQ 加密容器（仅解密路径）。
pub fn container_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 || data.len() % BLOCK != 0 {
        return None;
    }
    let mut stream = Vec::with_capacity(data.len());
    let mut p_prev = [0u8; 8];
    let mut c_prev = [0u8; 8];
    for (i, chunk) in data.chunks_exact(BLOCK).enumerate() {
        let c_i: [u8; 8] = chunk.try_into().ok()?;
        let input = if i == 0 { c_i } else { xor8(&p_prev, &c_i) };
        let p_i = tea_decrypt_block(&input, key);
        stream.extend_from_slice(&xor8(&p_i, &c_prev));
        p_prev = p_i;
        c_prev = c_i;
    }
    let v8 = (stream[0] & 0x07) as usize;
    if data.len() < v8 + 10 {
        return None;
    }
    let n = data.len() - v8 - 10;
    let start = v8 + 3;
    let payload = stream.get(start..start + n)?.to_vec();
    if stream[start + n..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(payload)
}

/// 解析 `be32(len) + data` 字段序列。
pub fn parse_fields(plain: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    let mut off = 0usize;
    while off + 4 <= plain.len() {
        let ln = u32::from_be_bytes(plain[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + ln > plain.len() {
            break;
        }
        fields.push(plain[off..off + ln].to_vec());
        off += ln;
    }
    fields
}

/// `guid = MD5(machine_id[..8] ‖ sn)`，返回 16 字节。
pub fn compute_guid(machine_id: &[u8], sn: &str) -> [u8; 16] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&machine_id[..machine_id.len().min(8)]);
    buf.extend_from_slice(sn.as_bytes());
    md5::compute(&buf).0
}

/// TEA 密钥 = `IOPlatformUUID` 字符串前 16 字节（不足补 0）。
pub fn key_from_uuid(uuid: &str) -> [u8; 16] {
    let raw = uuid.as_bytes();
    let mut key = [0u8; 16];
    let n = raw.len().min(16);
    key[..n].copy_from_slice(&raw[..n]);
    key
}

fn candidate(root: &Path) -> Option<PathBuf> {
    CANDIDATES
        .iter()
        .map(|segs| segs.iter().fold(root.to_path_buf(), |p, s| p.join(s)))
        .find(|p| p.exists())
}

/// 从数据根读取/计算 macOS 设备 guid（32 位小写 hex）。取不到返回 `None`。
pub fn read(data_root: &str) -> anyhow::Result<Option<String>> {
    let root = Path::new(data_root);
    if let Some(path) = candidate(root) {
        if let Ok(raw) = std::fs::read(&path) {
            if !raw.is_empty() {
                if let Some(uuid) = local_uuid() {
                    let key = key_from_uuid(&uuid);
                    if let Some(plain) = container_decrypt(&raw, &key) {
                        let fields = parse_fields(&plain);
                        if let Some(mid) = fields.first() {
                            if mid.len() >= 8 {
                                let sn = fields
                                    .get(1)
                                    .map(|b| String::from_utf8_lossy(b).into_owned())
                                    .unwrap_or_default();
                                return Ok(Some(hex::encode(compute_guid(mid, &sn))));
                            }
                        }
                    }
                }
            }
        }
    }
    // 回退：machine_id = MAC + 00 00，sn = disk0 序列号 / IOPlatformSerialNumber。
    let Some(mac) = local_mac_ioreg() else {
        return Ok(None);
    };
    let mut mid = [0u8; 8];
    mid[..6].copy_from_slice(&mac);
    let sn = local_disk_serial()
        .or_else(local_platform_serial)
        .unwrap_or_default();
    Ok(Some(hex::encode(compute_guid(&mid, &sn))))
}

// ---------- 本机硬件（仅 macOS；其它平台 None）----------

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ioreg_prop(class_name: &str, prop: &str) -> Option<String> {
    let text = run("ioreg", &["-rd1", "-c", class_name])?;
    for line in text.lines() {
        if line.contains(&format!("\"{prop}\"")) {
            if let Some((_, rhs)) = line.split_once('=') {
                return Some(rhs.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn local_uuid() -> Option<String> {
    ioreg_prop("IOPlatformExpertDevice", "IOPlatformUUID")
}

fn local_platform_serial() -> Option<String> {
    ioreg_prop("IOPlatformExpertDevice", "IOPlatformSerialNumber")
}

/// 主网卡 MAC（`IOEthernetInterface` 的 `IOMACAddress`）。
fn local_mac_ioreg() -> Option<[u8; 6]> {
    let text = run("ioreg", &["-rd1", "-c", "IOEthernetInterface"])?;
    for line in text.lines() {
        if line.contains("\"IOMACAddress\"") {
            let rhs = line.split_once('=')?.1;
            let hx: String = rhs.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hx.len() >= 12 {
                let bytes = hex::decode(&hx[..12]).ok()?;
                return bytes.try_into().ok();
            }
        }
    }
    None
}

/// `/dev/disk0` 的序列号（`diskutil info`）。
fn local_disk_serial() -> Option<String> {
    let text = run("diskutil", &["info", "/dev/disk0"])?;
    for line in text.lines() {
        if line.contains("Serial Number") || line.contains("设备序列号") {
            return line.split_once(':').map(|(_, v)| v.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tea_block_vector() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let block = hex::decode("0001020304050607").unwrap();
        assert_eq!(hex::encode(tea_encrypt_block(&block, &key)), "6328a50896bde3c8");
    }

    #[test]
    fn key_from_uuid_pads() {
        assert_eq!(key_from_uuid("0123456789abcdefEXTRA"), *b"0123456789abcdef");
        assert_eq!(key_from_uuid("short"), *b"short\0\0\0\0\0\0\0\0\0\0\0");
    }

    /// 真实 macOS `machineid-info`（48 字节）+ 全零 IOPlatformUUID -> guid 实测值。
    #[test]
    fn decrypt_real_machineid_info() {
        let raw = hex::decode(concat!(
            "062c59f4bd7972c3baeab0dd857d9482",
            "d57ecafe96b7ec4d566e416871d7e829",
            "0d117016cd94f644ea968bc641bae40d",
        ))
        .unwrap();
        let key = key_from_uuid("00000000-0000-0000-0000-000000000000");
        let plain = container_decrypt(&raw, &key).expect("container decrypt");
        let fields = parse_fields(&plain);
        assert_eq!(hex::encode(&fields[0]), "525400c918270000");
        assert_eq!(String::from_utf8_lossy(&fields[1]), "QM00021             ");
        let guid = hex::encode(compute_guid(&fields[0], &String::from_utf8_lossy(&fields[1])));
        assert_eq!(guid, "110cac8ab81e1b7dca6e3f48b1127d92");
    }

    #[test]
    fn compute_guid_selftest_vector() {
        let mid = hex::decode("aabbccddeeff0011").unwrap();
        assert_eq!(
            hex::encode(compute_guid(&mid, "C02TEST")),
            "99902c9e4658f3495eac9932da8de575"
        );
    }
}
