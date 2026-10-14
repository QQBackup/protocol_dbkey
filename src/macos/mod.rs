//! macOS 适配层：数据根/安装根定位、guid、appid/qua、key_meta、A1 解密。
//!
//! 全部离线、无 SIP / 无 root 依赖：只读文件系统（QQ 数据根 + `/Applications`）。

pub mod appid;
pub mod guid;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

/// macOS 沙盒容器数据根（与 linux 的 `~/.config/QQ` 同布局）。
pub fn default_data_root(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Containers")
        .join("com.tencent.qq")
        .join("Data")
        .join("Library")
        .join("Application Support")
        .join("QQ")
}

/// 数据根候选（override 优先，其次默认容器路径）。
pub fn candidate_roots(home: &Path, override_root: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(o) = override_root {
        if o.exists() {
            out.push(o.to_path_buf());
        }
    }
    out.push(default_data_root(home));
    out.dedup();
    out
}

/// 第一个存在的候选数据根。
pub fn pick_root(home: &Path, override_root: Option<&Path>) -> Option<PathBuf> {
    candidate_roots(home, override_root).into_iter().find(|p| p.exists())
}

/// 两个 `login.db` 路径（主 `global/nt_db` 优先，备 `nt_qq/global/nt_db`）。
pub fn login_dbs(home: &Path, override_root: Option<&Path>) -> Vec<PathBuf> {
    let roots = candidate_roots(home, override_root);
    let mut out = Vec::new();
    let patterns: [&[&str]; 2] = [
        &["global", "nt_db", "login.db"],
        &["nt_qq", "global", "nt_db", "login.db"],
    ];
    for rel in patterns {
        for root in &roots {
            let p = rel.iter().fold(root.clone(), |acc, s| acc.join(s));
            if p.exists() {
                out.push(p);
                break;
            }
        }
    }
    out.dedup();
    out
}

/// `accountDirName(uid) = nt_qq_<md5(md5(uid) + "nt_kernel")>`。
pub fn account_dir_name(uid: &str) -> String {
    let inner = hex::encode(md5::compute(uid.as_bytes()).0);
    let hash = hex::encode(md5::compute(format!("{inner}nt_kernel").as_bytes()).0);
    format!("nt_qq_{hash}")
}

/// 某账号 `<root>/nt_qq_<hash>/<segments>` 第一条存在的路径。
pub fn account_path(
    home: &Path,
    override_root: Option<&Path>,
    uid: &str,
    segments: &[&str],
) -> Option<PathBuf> {
    if uid.is_empty() {
        return None;
    }
    let dir = account_dir_name(uid);
    for root in candidate_roots(home, override_root) {
        let mut p = root.join(&dir);
        for s in segments {
            p = p.join(s);
        }
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// 账号的 `nt_msg.db` 路径。
pub fn nt_msg_db(home: &Path, override_root: Option<&Path>, uid: &str) -> Option<PathBuf> {
    account_path(home, override_root, uid, &["nt_db", "nt_msg.db"])
}

/// 读 `nt_msg.db` 头 `0x2f..0xaf` 的 128 字节 key_meta（dbSalt，128 位小写 hex）。
/// 读不到 / 格式非法返回 `None`。
pub fn read_key_meta(db_path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(db_path).ok()?;
    f.seek(SeekFrom::Start(0x2f)).ok()?;
    let mut buf = [0u8; 0x80];
    f.read_exact(&mut buf).ok()?;
    let s = String::from_utf8_lossy(&buf).into_owned();
    if s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

/// 解密 `login.db` 里 `[1004]` 的 A1 payload（`[IV][be32][AES-128-CBC]`）内层。
///
/// 密钥是本机设备 guid 的 16 字节原文。任何校验失败返回 `None`。
pub fn decrypt_a1_payload(blob: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    if blob.len() < 20 || key.len() != 16 {
        return None;
    }
    if u32::from_be_bytes(blob[16..20].try_into().ok()?) as usize != blob.len() - 16 {
        return None;
    }
    let iv = &blob[..16];
    let ct = &blob[20..];
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let cipher = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).ok()?;
    let mut buf = ct.to_vec();
    let plain = cipher.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;
    // 内层：`[be32 内层长(含自身 4 字节)][payload]`
    if plain.len() < 4 {
        return None;
    }
    let inner_len = u32::from_be_bytes(plain[0..4].try_into().ok()?) as usize;
    if inner_len < 4 || inner_len > plain.len() {
        return None;
    }
    Some(plain[4..inner_len].to_vec())
}

// ---------- QQ 安装根（wrapper.node / major.node）----------

/// QQ 数据根下顺带把设备 guid 算出来（用于 A1 解密）。取不到返回 `None`。
pub fn device_guid(root: &Path) -> Option<String> {
    guid::read(&root.to_string_lossy()).ok().flatten()
}

/// `QQ.app` 候选（标准安装 + 用户级安装）。
fn app_bundles(home: &Path) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Applications/QQ.app"),
        home.join("Applications/QQ.app"),
    ]
}

/// `<QQ.app>/Contents/Resources/app`（wrapper.node / major.node 所在目录）。
/// `override_install_root` 直接给定该目录时优先。
fn resources_app(home: &Path, override_install_root: Option<&Path>) -> Option<PathBuf> {
    if let Some(o) = override_install_root {
        if o.is_dir() {
            return Some(o.to_path_buf());
        }
    }
    app_bundles(home)
        .into_iter()
        .map(|b| b.join("Contents/Resources/app"))
        .find(|p| p.is_dir())
}

/// `wrapper.node` 路径。
pub fn wrapper_node(home: &Path) -> Result<PathBuf> {
    wrapper_node_for(home, None)
}

/// `wrapper.node` 路径（可指定 Resources/app 覆盖）。
pub fn wrapper_node_for(home: &Path, override_install_root: Option<&Path>) -> Result<PathBuf> {
    let app = resources_app(home, override_install_root)
        .ok_or_else(|| anyhow!("未找到 QQ.app/Contents/Resources/app（请确认已安装 QQ）"))?;
    let p = app.join("wrapper.node");
    if p.exists() {
        Ok(p)
    } else {
        bail!("{} 不存在", p.display())
    }
}

/// `major.node` 路径。
pub fn major_node(home: &Path) -> Result<PathBuf> {
    major_node_for(home, None)
}

/// `major.node` 路径（可指定 Resources/app 覆盖）。
pub fn major_node_for(home: &Path, override_install_root: Option<&Path>) -> Result<PathBuf> {
    let app = resources_app(home, override_install_root)
        .ok_or_else(|| anyhow!("未找到 QQ.app/Contents/Resources/app（请确认已安装 QQ）"))?;
    let p = app.join("major.node");
    if p.exists() {
        Ok(p)
    } else {
        bail!("{} 不存在", p.display())
    }
}

/// 解析 `major.node` 得到 appid / qua / version / build。
pub fn resolve_appid_info(home: &Path) -> Result<appid::ResolveResult> {
    resolve_appid_info_opt(home, None)
}

/// 解析 `major.node`（可指定 Resources/app 覆盖）。
pub fn resolve_appid_info_opt(
    home: &Path,
    override_install_root: Option<&Path>,
) -> Result<appid::ResolveResult> {
    let path = major_node_for(home, override_install_root).context("定位 major.node")?;
    appid::resolve_from_path(&path).map_err(|e| anyhow!("解析 major.node 失败：{e}"))
}
