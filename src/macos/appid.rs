//! `major.node` appid / QUA 提取器（macOS）。
//!
//! 扫描当前 QQ 构建里硬编码的值：
//! * **appid**：锚点 `QQAppId/537xxxxxx`（登录协议真正用的 appid / SSO subAppId）；
//! * **QUA**：锚点 `V1_XXX_NQ_<ver>_<build>_GW_X`；
//! * **version**：从 QUA 里解出的 `3.2.31` / `51102`。

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResult {
    pub appid: String,
    pub qua: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    AppidNotFound,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Io(e) => write!(f, "读取文件失败: {e}"),
            ResolveError::AppidNotFound => write!(
                f,
                "major.node 里没找到 QQAppId/ 锚点（版本异常或二进制被压缩？）"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}
impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> Self {
        ResolveError::Io(e)
    }
}

pub fn resolve_from_path<P: AsRef<Path>>(path: P) -> Result<ResolveResult, ResolveError> {
    let mut file = File::open(path)?;
    let cap = file.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut buf = Vec::with_capacity(cap);
    file.read_to_end(&mut buf)?;
    resolve_from_bytes(&buf)
}

pub fn resolve_from_bytes(data: &[u8]) -> Result<ResolveResult, ResolveError> {
    let appid = find_appid(data).ok_or(ResolveError::AppidNotFound)?;
    let qua = find_qua(data);
    let (version, build) = match &qua {
        Some(q) => parse_qua_version(q),
        None => (None, None),
    };
    Ok(ResolveResult {
        appid,
        qua,
        version,
        build,
    })
}

/// 扫描 `QQAppId/` 后紧跟的数字串。
fn find_appid(data: &[u8]) -> Option<String> {
    const ANCHOR: &[u8] = b"QQAppId/";
    let end = data.len();
    let mut i = 0usize;
    while i + ANCHOR.len() < end {
        if data[i] == b'Q' && &data[i..i + ANCHOR.len()] == ANCHOR {
            let mut j = i + ANCHOR.len();
            let start = j;
            while j < end && data[j].is_ascii_digit() {
                j += 1;
            }
            if j - start >= 5 {
                return Some(String::from_utf8_lossy(&data[start..j]).into_owned());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

/// 扫描 `V1_XXX_NQ_..._GW_X` QUA 串。
fn find_qua(data: &[u8]) -> Option<String> {
    const HEAD: &[u8] = b"V1_";
    let end = data.len();
    let mut i = 0usize;
    while i + HEAD.len() < end {
        if data[i] == b'V' && &data[i..i + HEAD.len()] == HEAD {
            if let Some(len) = try_match_qua(&data[i..]) {
                return Some(String::from_utf8_lossy(&data[i..i + len]).into_owned());
            }
        }
        i += 1;
    }
    None
}

/// 从 `slice` 起始匹配一个完整 QUA，返回其长度。
fn try_match_qua(slice: &[u8]) -> Option<usize> {
    // 必须以 V1_ + 3 个大写字母 + _NQ_ 开头。
    if slice.len() < 4 || &slice[0..3] != b"V1_" {
        return None;
    }
    if slice.len() < 6 || !slice[3..6].iter().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    const MAX_QUA: usize = 64;
    let limit = slice.len().min(MAX_QUA);
    let mut k = 6;
    while k + 4 <= limit {
        if &slice[k..k + 4] == b"_GW_" {
            let after = k + 4;
            if after < slice.len() && slice[after].is_ascii_uppercase() {
                return Some(after + 1);
            }
            return None;
        }
        let b = slice[k];
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
            return None;
        }
        k += 1;
    }
    None
}

fn parse_qua_version(qua: &str) -> (Option<String>, Option<String>) {
    // V1_LNX_NQ_3.2.31_51102_GW_B
    let parts: Vec<&str> = qua.split('_').collect();
    // ["V1","LNX","NQ","3.2.31","51102","GW","B"]
    if parts.len() >= 5 {
        (Some(parts[3].to_string()), Some(parts[4].to_string()))
    } else {
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_appid() {
        assert_eq!(find_appid(b"...QQAppId/537376497...").as_deref(), Some("537376497"));
    }

    #[test]
    fn test_find_qua_mac() {
        assert_eq!(
            find_qua(b"...V1_MAC_NQ_7.0.0_52194_GW_B...").as_deref(),
            Some("V1_MAC_NQ_7.0.0_52194_GW_B")
        );
    }

    #[test]
    fn test_parse_qua_version() {
        let (v, b) = parse_qua_version("V1_MAC_NQ_7.0.0_52194_GW_B");
        assert_eq!(v.as_deref(), Some("7.0.0"));
        assert_eq!(b.as_deref(), Some("52194"));
    }
}
