//! 手写解密 QQ NT 的 `login.db`（不引 sqlcipher / openssl）并读取账号列表。
//!
//! | 文件               | 职责                                              |
//! |--------------------|---------------------------------------------------|
//! | [`cipher`]         | SQLCipher 算法对（page-HMAC × KDF-HMAC）+ PBKDF2  |
//! | [`decrypt`]        | 逐页 AES-256-CBC 解密 + 暴力探测算法对            |
//! | [`wal_merge`]      | 合并 `-wal`（借 SQLite checkpoint 回放）          |
//! | [`db`]             | 读 `login_table`（uin/uid/nick）+ WAL 合并入口     |

pub mod cipher;
pub mod db;
pub mod decrypt;
pub mod wal_merge;

pub use cipher::Algo;
pub use db::read_accounts_merged;
pub use decrypt::{detect_algo, decrypt_database, decrypt_wal};

/// `login.db` 固定的 pre-login 密钥（不随账号变）。
pub const PRE_LOGIN_KEY: &[u8] = b"BD156D6710D54D8782F4";
