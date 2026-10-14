//! TEA 加解密，对齐 Lagrange 的 `TeaProvider`
//! （`Lagrange.Core/Utility/Cryptography/TeaProvider.cs`）。
//!
//! SSO 包体在 service 层用 d2key（或全零「空 key」）加密，就是这套算法：
//!
//! * 8 字节一块、**大端**；32 轮、delta `0x9E3779B9`；
//! * 每个块前先与前一状态异或（`plainXor`/`prevXor` 链），再进 TEA；
//! * 填充头：`fill = 10 - ((len + 1) & 7)`，`out[0] = (fill - 3) | 0xF8`，
//!   明文从 `out[fill]` 开始，尾部再补 7 字节；密文总长 `fill + len + 7`
//!   （必为 8 的倍数）。
//!
//! 已知向量：`E(0001020304050607, key=000102030405060708090a0b0c0d0e0f)`
//! = `6328a50896bde3c8`（见 [`tests::block_matches_known_vector`]）。

/// TEA 的黄金比例常量。
const DELTA: u32 = 0x9E37_79B9;

/// 把 16 字节 key 按**大端**拆成 4 个 `u32`。
fn key_words(key: &[u8]) -> [u32; 4] {
    let mut k = [0u32; 4];
    for (i, slot) in k.iter_mut().enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(&key[i * 4..i * 4 + 4]);
        *slot = u32::from_be_bytes(b);
    }
    k
}

/// 轮数。注意是 **16 轮**（不是教科书的 32）：Lagrange 把 16 组 `x/y` 更新展开写死，
/// `sum` 累加到 `delta * 16 = 0xE3779B90`。用 [`tests::block_matches_known_vector`]
/// 的已知向量钉住这一点。
const ROUNDS: u32 = 16;

/// TEA 的 16 轮加密（单块，`x` 高 32 位、`y` 低 32 位）。
fn encrypt_block(mut x: u32, mut y: u32, k: &[u32; 4]) -> (u32, u32) {
    let (a, b, c, d) = (k[0], k[1], k[2], k[3]);
    let mut sum: u32 = 0;
    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);
        x = x.wrapping_add(
            y.wrapping_add(sum) ^ (y << 4).wrapping_add(a) ^ (y >> 5).wrapping_add(b),
        );
        y = y.wrapping_add(
            x.wrapping_add(sum) ^ (x << 4).wrapping_add(c) ^ (x >> 5).wrapping_add(d),
        );
    }
    (x, y)
}

/// TEA 的 16 轮解密（单块）。
fn decrypt_block(mut x: u32, mut y: u32, k: &[u32; 4]) -> (u32, u32) {
    let (a, b, c, d) = (k[0], k[1], k[2], k[3]);
    let mut sum: u32 = DELTA.wrapping_mul(ROUNDS);
    for _ in 0..ROUNDS {
        y = y.wrapping_sub(
            x.wrapping_add(sum) ^ (x << 4).wrapping_add(c) ^ (x >> 5).wrapping_add(d),
        );
        x = x.wrapping_sub(
            y.wrapping_add(sum) ^ (y << 4).wrapping_add(a) ^ (y >> 5).wrapping_add(b),
        );
        sum = sum.wrapping_sub(DELTA);
    }
    (x, y)
}

/// 密文长度（对齐 `TeaProvider.GetCipherLength`）。
pub fn cipher_len(data_len: usize) -> usize {
    (10 - ((data_len + 1) & 7)) + data_len + 7
}

fn read_be_u64(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    u64::from_be_bytes(buf)
}

/// 填充用的伪随机字节。这里不引入 `rand`：只用于填充区，解密不依赖其取值，
/// 用亚秒纳秒播种的 xorshift 即可避免同明文同密文。
struct Fill(u64);

impl Fill {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x2545_F491_4F6C_DD1D);
        Fill(nanos | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// 加密：返回长度必为 8 倍数的密文（对齐 `TeaProvider.Encrypt`）。
///
/// `key` 必须恰好 16 字节。
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16, "TEA key 必须是 16 字节");
    let k = key_words(key);
    let fill = 10 - ((data.len() + 1) & 7);
    let total = fill + data.len() + 7;

    let mut out = vec![0u8; total];
    // 填充区：低位 3 位承载长度元信息，其余随意填。
    let mut rng = Fill::new();
    for chunk in out[..fill].chunks_mut(8) {
        let v = rng.next_u64().to_be_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&v[..n]);
    }
    out[0] = ((fill - 3) as u8) | 0xF8;
    out[fill..fill + data.len()].copy_from_slice(data);

    let mut plain_xor: u64 = 0;
    let mut prev_xor: u64 = 0;
    let mut i = 0usize;
    while i < total {
        let block = read_be_u64(&out[i..]) ^ plain_xor;
        let (x, y) = encrypt_block((block >> 32) as u32, block as u32, &k);
        plain_xor = (((x as u64) << 32) | y as u64) ^ prev_xor;
        prev_xor = block;
        out[i..i + 8].copy_from_slice(&plain_xor.to_be_bytes());
        i += 8;
    }
    out
}

/// 解密（对齐 `TeaProvider.Decrypt(byte[])`）：返回去掉填充头与尾部 7 字节的明文。
pub fn decrypt(data: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    assert_eq!(key.len(), 16, "TEA key 必须是 16 字节");
    if data.is_empty() || data.len() % 8 != 0 {
        anyhow::bail!("TEA 密文长度必须是非零的 8 的倍数，实际 {}", data.len());
    }
    let k = key_words(key);
    let mut out = vec![0u8; data.len()];
    let mut plain_xor: u64 = 0;
    let mut prev_xor: u64 = 0;
    let mut i = 0usize;
    while i < data.len() {
        let block = read_be_u64(&data[i..]);
        plain_xor ^= block;
        let (x, y) = decrypt_block((plain_xor >> 32) as u32, plain_xor as u32, &k);
        plain_xor = ((x as u64) << 32) | y as u64;
        out[i..i + 8].copy_from_slice(&(plain_xor ^ prev_xor).to_be_bytes());
        prev_xor = block;
        i += 8;
    }
    // 填充长度要从**解密后**的首字节取（对齐 `TeaProvider.CreateDecryptSpan`，
    // 而不是从密文取）。
    let fill = (out[0] & 7) as usize + 3;
    if out.len() < fill + 7 {
        anyhow::bail!("TEA 解密结果过短：len={} fill={}", out.len(), fill);
    }
    Ok(out[fill..out.len() - 7].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 单块已知向量：`E(0001020304050607)`，与 `guid/macos.rs` 的 TEA 测试同源。
    /// 它把「16 轮 + 大端 + delta」这三点钉死。
    #[test]
    fn block_matches_known_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let k = key_words(&key);
        let (x, y) = encrypt_block(0x0001_0203, 0x0405_0607, &k);
        assert_eq!(((x as u64) << 32) | y as u64, 0x6328_a508_96bd_e3c8);
        assert_eq!(decrypt_block(x, y, &k), (0x0001_0203, 0x0405_0607));
    }

    #[test]
    fn cipher_length_is_always_a_multiple_of_eight() {
        for len in 0..64usize {
            assert_eq!(cipher_len(len) % 8, 0, "len={len}");
        }
    }

    #[test]
    fn round_trips_various_lengths() {
        let key = [0x11u8; 16];
        for len in 0..64usize {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let cipher = encrypt(&plain, &key);
            assert_eq!(cipher.len(), cipher_len(len), "len={len}");
            assert_eq!(decrypt(&cipher, &key).unwrap(), plain, "len={len}");
        }
    }

    #[test]
    fn zero_key_round_trips() {
        let key = [0u8; 16];
        let plain = b"hello nt sso".to_vec();
        let cipher = encrypt(&plain, &key);
        assert_eq!(decrypt(&cipher, &key).unwrap(), plain);
    }

    #[test]
    fn rejects_malformed_ciphertext() {
        let key = [0u8; 16];
        assert!(decrypt(&[], &key).is_err());
        assert!(decrypt(&[0u8; 7], &key).is_err());
    }
}
