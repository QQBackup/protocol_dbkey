//! OIDB 信封组包 / 解包（只保留 0xcde_2 取数据库密钥所需）。
//!
//! `0xcde_2`（`OidbSvcTrpcTcp.0xcde_2`）：用 key_meta（目标库头 `0x2f..0xaf`
//! 的 128 字节 dbSalt）向服务端换 dbkey。走登录连接，加密固定 `EncryptD2Key`
//! （协议 12），**不签名**（真机抓包 reserved 里没有 tag 24）。

use anyhow::{anyhow, Result};
use prost::Message;

use crate::sso::packer::SsoResponse;

#[derive(Clone, PartialEq, Message)]
pub struct OidbBase {
    #[prost(uint32, tag = "1")]
    pub command: u32,
    #[prost(uint32, tag = "2")]
    pub sub_command: u32,
    #[prost(uint32, tag = "3")]
    pub error_code: u32,
    #[prost(bytes, tag = "4")]
    pub body: Vec<u8>,
    #[prost(string, tag = "5")]
    pub error_msg: String,
    #[prost(int32, tag = "12")]
    pub reserved: i32,
}

impl OidbBase {
    pub fn new(command: u32, sub_command: u32, body: Vec<u8>) -> Self {
        Self {
            command,
            sub_command,
            body,
            error_code: 0,
            error_msg: String::new(),
            reserved: 0,
        }
    }
}

/// 组一个 OIDB 请求信封并给出命令串。
/// `is_uid=true` 时外层 `reserved=1`（UIN-form 变体）。
pub fn build_oidb_envelope(
    command: u32,
    sub_command: u32,
    body: Vec<u8>,
    is_uid: bool,
) -> (String, Vec<u8>) {
    let mut envelope = OidbBase::new(command, sub_command, body);
    if is_uid {
        envelope.reserved = 1;
    }
    (
        format!("OidbSvcTrpcTcp.0x{:x}_{}", command, sub_command),
        envelope.encode_to_vec(),
    )
}

/// 解一条 OIDB 应答：先看 SSO `ret_code`，再看外层 `error_code`，最后取内层 body。
pub fn decode_oidb_reply(reply: &SsoResponse) -> Result<Vec<u8>> {
    if reply.ret_code != 0 {
        return Err(anyhow!(
            "Reply status error: {} ({})",
            reply.ret_code,
            reply.extra
        ));
    }
    let envelope = OidbBase::decode(&reply.payload[..])?;
    if envelope.error_code != 0 {
        return Err(anyhow!(
            "OIDB error {}: {}",
            envelope.error_code,
            envelope.error_msg
        ));
    }
    Ok(envelope.body)
}

/// `0xcde_2` 命令号 / 子命令号。
pub const DECRYPT_KEY_COMMAND: u32 = 0xcde;
pub const DECRYPT_KEY_SUB_COMMAND: u32 = 2;

/// 请求内层 `info`：`{ dbSalt }`。
#[derive(Clone, PartialEq, Message)]
pub struct DecryptKeyReqInfo {
    #[prost(string, tag = "1")]
    pub db_salt: String,
}

/// `0xcde_2` 请求内层：`{ info }`（只发 tag2）。
#[derive(Clone, PartialEq, Message)]
pub struct DecryptKeyReq {
    #[prost(message, optional, tag = "2")]
    pub info: Option<DecryptKeyReqInfo>,
}

/// 应答内层 `info`：`{ dbKey }`。
#[derive(Clone, PartialEq, Message)]
pub struct DecryptKeyRspInfo {
    #[prost(string, tag = "1")]
    pub db_key: String,
}

/// `0xcde_2` 应答内层：`{ info }`。
#[derive(Clone, PartialEq, Message)]
pub struct DecryptKeyRsp {
    #[prost(message, optional, tag = "2")]
    pub info: Option<DecryptKeyRspInfo>,
}

/// 组 `0xcde_2` 的**内层**请求 body：`{ info: { dbSalt } }`。
pub fn build_decrypt_key_body(db_salt: &str) -> Vec<u8> {
    DecryptKeyReq {
        info: Some(DecryptKeyReqInfo {
            db_salt: db_salt.to_string(),
        }),
    }
    .encode_to_vec()
}

/// 解 `0xcde_2` 的**内层**应答 body，取 `info.dbKey`。
pub fn decode_decrypt_key_reply(body: &[u8]) -> Result<String> {
    let rsp = DecryptKeyRsp::decode(body)?;
    rsp.info
        .map(|i| i.db_key)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| anyhow!("0xcde_2 应答缺少 info.dbKey"))
}
