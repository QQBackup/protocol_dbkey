//! 读取**已解密**的 `login.db`（明文 SQLite）枚举本机账号。
//!
//! SQLCipher 层已被 [`crate::login_db::decrypt`] 的手写 AES 逐页解密剥掉，这里
//! 就是一个普通 SQLite 文件，用 `rusqlite`（`bundled`，**非** sqlcipher、无
//! openssl）打开读 `login_table`。
//!
//! 列（QQ 私有 schema 里的数字字符串 key）：
//! * `"1000"` = uin
//! * `"1001"` = uid
//! * `"1002"` = avatarUrl
//! * `"1007"` = user_name（昵称）
//! * `"1004"` = A1 记录（`[IV][be32][AES-128-CBC(guid)]` 原样 blob）
//! * `"1008"` = lastLoginAt（unix 秒）

use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::login_db::wal_merge::{self, Decrypted};
use crate::login_db::{detect_algo, Algo, PRE_LOGIN_KEY};

/// `login.db` 里的一行账号快照。
#[derive(Debug, Clone)]
pub struct Account {
    pub uin: String,
    pub uid: String,
    pub nick: String,
    pub avatar_url: String,
    /// `[1004]` 的原始 A1 blob（可能为空）。
    pub a1_blob: Vec<u8>,
    pub last_login_at: i64,
}

/// 解密 `login.db`、合并其 `-wal`，并返回账号列表 + 探测到的算法对。
pub fn read_accounts(path: &Path) -> io::Result<(Vec<Account>, Algo, Decrypted)> {
    let bytes = std::fs::read(path)?;
    let verified = detect_algo(&bytes, PRE_LOGIN_KEY).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "无法解密 login.db：12 组 (page-HMAC × KDF-HMAC) 都与内置 pre-login key 不匹配 \
             （客户端布局可能已变）",
        )
    })?;
    let merged = wal_merge::decrypt_db_bytes(
        &bytes,
        &wal_merge::wal_sidecar(path),
        PRE_LOGIN_KEY,
        &verified.algo,
    )?;
    let accounts = query_login_table(&merged.bytes)?;
    Ok((accounts, verified.algo, merged))
}

/// 读多个候选 `login.db`（macOS：`global/nt_db` 主 + `nt_qq/global/nt_db` 备），
/// 按 uin 合并去重，靠前的路径优先。全部读不出时才报错。
pub fn read_accounts_merged(paths: &[PathBuf]) -> io::Result<(Vec<Account>, Algo)> {
    let mut merged: Vec<Account> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut algo: Option<Algo> = None;
    let mut last_err: Option<io::Error> = None;

    for path in paths {
        if !path.exists() {
            continue;
        }
        match read_accounts(path) {
            Ok((accounts, a, _)) => {
                algo.get_or_insert(a);
                for acc in accounts {
                    if seen.insert(acc.uin.clone()) {
                        merged.push(acc);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    match algo {
        Some(a) => Ok((merged, a)),
        None => Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "没有可读的 login.db 候选")
        })),
    }
}

/// 把明文 SQLite 镜像落到临时文件，读 `login_table`。
fn query_login_table(plain: &[u8]) -> io::Result<Vec<Account>> {
    let tmp = tempfile_path();
    std::fs::write(&tmp, plain)?;
    let result = (|| -> rusqlite::Result<Vec<Account>> {
        let conn = Connection::open_with_flags(
            &tmp,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        let mut stmt = conn.prepare(
            r#"SELECT "1000", "1001", "1002", "1007", "1004", "1008" FROM login_table"#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Account {
                uin: value_to_string(row.get_ref(0)?),
                uid: value_to_string(row.get_ref(1)?),
                avatar_url: value_to_string(row.get_ref(2)?),
                nick: value_to_string(row.get_ref(3)?),
                a1_blob: value_to_blob(row.get_ref(4)?),
                last_login_at: value_to_i64(row.get_ref(5)?),
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    })();
    let _ = std::fs::remove_file(&tmp);
    result.map_err(|e| io::Error::other(format!("login_table 读取失败：{e}")))
}

fn value_to_string(v: rusqlite::types::ValueRef<'_>) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => r.to_string(),
        ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        ValueRef::Null => String::new(),
    }
}

fn value_to_blob(v: rusqlite::types::ValueRef<'_>) -> Vec<u8> {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Blob(b) => b.to_vec(),
        ValueRef::Text(t) => t.to_vec(),
        _ => Vec::new(),
    }
}

fn value_to_i64(v: rusqlite::types::ValueRef<'_>) -> i64 {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Integer(i) => i,
        ValueRef::Real(r) => r as i64,
        ValueRef::Text(t) => String::from_utf8_lossy(t).trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// 进程 id + 栈地址给出够用的唯一临时路径（单发用途，不引 tempfile crate）。
fn tempfile_path() -> PathBuf {
    let mut dir = std::env::temp_dir();
    let salt = &dir as *const _ as usize;
    dir.push(format!("qqdbkey_login_{}_{salt:x}.db", std::process::id()));
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真库冒烟：本地存在从 VM 拷出的 login.db 时验证解密 + 账号读取。
    /// 运行：登录 db 路径由 `QQDBKEY_TEST_LOGIN_DB` 指定（默认 /tmp/vm_login.db）。
    #[test]
    fn real_login_db_smoke() {
        let path = std::env::var("QQDBKEY_TEST_LOGIN_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/vm_login.db"));
        if !path.exists() {
            eprintln!("skip: {} 不存在", path.display());
            return;
        }
        let (accounts, algo) = read_accounts_merged(&[path]).expect("read login.db");
        eprintln!("algo page={:?} kdf={:?}", algo.page, algo.kdf);
        for a in &accounts {
            eprintln!(
                "uin={} uid={} nick={} a1_blob={} last={}",
                a.uin,
                a.uid,
                a.nick,
                a.a1_blob.len(),
                a.last_login_at
            );
        }
        assert!(!accounts.is_empty(), "应至少解出一个账号");
    }
}
