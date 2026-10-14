//! wtlogin（PC 快登 / 二维码）用到的 protobuf 消息。
//!
//! 字段号与语义逐条对齐 Lagrange.Core `Internal/Packets/Login/*.cs`：
//! * `NTEcdh.cs` —— `KeyExchange*` / `NTLoginForwardRequest`；
//! * `NTLogin.cs` —— `NTLoginCommon/Head/...` 与 `NTLoginTickets`。
//!
//! 对齐要点：Lagrange 全部标了 `IgnoreDefaultFields = true`，即**零值字段不写**。
//! prost 里用 `Option<T>` 表达这一点（`None` 不编码），所以凡是可能为空的字段都
//! 定义成 `Option`。请求/应答共用同一套结构，缺省字段不会污染线上字节。

use prost::Message;

// ─── trpc.login.ecdh.EcdhService.SsoKeyExchange ────────────────────────────

/// `KeyExchangeRequest`（NTEcdh.cs）。
#[derive(Clone, PartialEq, Message)]
pub struct KeyExchangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub r#type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub secret: Vec<u8>,
    #[prost(int64, tag = "4")]
    pub timestamp: i64,
    #[prost(bytes = "vec", tag = "5")]
    pub verify_hash: Vec<u8>,
}

/// `KeyExchangeResponse`。字段 2 语义未知（Lagrange 保留但没读）。
#[derive(Clone, PartialEq, Message)]
pub struct KeyExchangeResponse {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub secret: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub field2: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub public_key: Option<Vec<u8>>,
}

/// `KeyExchangeRequestBuf`（pb_buf）：AES-GCM 加密前的明文。
#[derive(Clone, PartialEq, Message)]
pub struct KeyExchangeRequestBuf {
    #[prost(string, optional, tag = "1")]
    pub uin: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub guid: Option<Vec<u8>>,
}

/// `KeyExchangeResponseSecret`：AES-GCM 解密后的会话物料。
#[derive(Clone, PartialEq, Message)]
pub struct KeyExchangeResponseSecret {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub session_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub session_ticket: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "3")]
    pub expiration: Option<u32>,
}

/// `NTLoginForwardRequest`：快登/密码登录共用的外层信封。
///
/// PC 端只用 `SessionTicket(1) + Buffer(3, AES-GCM(NTLoginCommon)) + Type(4)=1`；
/// `SecBuffer(5)` 是安卓路径（`NTLoginAndroidCommon`）用的。
#[derive(Clone, PartialEq, Message)]
pub struct NtLoginForwardRequest {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub session_ticket: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub buffer: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "4")]
    pub r#type: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub sec_buffer: Option<Vec<u8>>,
}

// ─── NTLoginCommon（Head + Body）───────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginCommon {
    #[prost(message, optional, tag = "1")]
    pub head: Option<NtLoginHead>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub body: Option<Vec<u8>>,
}

/// 请求只填 `UserInfo/ClientInfo/AppInfo/SdkInfo`；应答会带 `ErrorInfo/Cookie/...`。
#[derive(Clone, PartialEq, Message)]
pub struct NtLoginHead {
    #[prost(message, optional, tag = "1")]
    pub user_info: Option<NtLoginUserInfo>,
    #[prost(message, optional, tag = "2")]
    pub client_info: Option<NtLoginClientInfo>,
    #[prost(message, optional, tag = "3")]
    pub app_info: Option<NtLoginAppInfo>,
    #[prost(message, optional, tag = "4")]
    pub error_info: Option<NtLoginErrorInfo>,
    #[prost(message, optional, tag = "5")]
    pub cookie: Option<NtLoginCookie>,
    #[prost(message, optional, tag = "7")]
    pub sdk_info: Option<NtLoginSdkInfo>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginUserInfo {
    #[prost(string, optional, tag = "1")]
    pub account: Option<String>,
    #[prost(uint32, optional, tag = "2")]
    pub country_code: Option<u32>,
}

/// `Platform`：Windows=4 / Mac=5 / Linux=7。
#[derive(Clone, PartialEq, Message)]
pub struct NtLoginClientInfo {
    #[prost(string, optional, tag = "1")]
    pub device_type: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub device_name: Option<String>,
    #[prost(uint32, optional, tag = "3")]
    pub platform: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub guid: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    pub pubno: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub client_ver: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub client_type: Option<u32>,
    #[prost(uint32, optional, tag = "8")]
    pub sso_ver: Option<u32>,
}

/// 真机抓包只发 `Version/AppId/AppName` 三个字段（`Qua` 等留空不写）。
#[derive(Clone, PartialEq, Message)]
pub struct NtLoginAppInfo {
    #[prost(string, optional, tag = "1")]
    pub version: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub app_id: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub app_name: Option<String>,
    #[prost(uint32, optional, tag = "4")]
    pub client_a1_version: Option<u32>,
    #[prost(string, optional, tag = "5")]
    pub qua: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginSdkInfo {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginCookie {
    #[prost(string, optional, tag = "1")]
    pub cookie_content: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginErrorInfo {
    #[prost(uint64, optional, tag = "1")]
    pub err_code: Option<u64>,
    #[prost(string, optional, tag = "2")]
    pub str_tips_title: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub str_tips_content: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub str_jump_wording: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub str_jump_url: Option<String>,
}

// ─── EasyLogin body ────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginEasyLoginReqBody {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub a1: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginEasyLoginRspBody {
    #[prost(message, optional, tag = "1")]
    pub tickets: Option<NtLoginTickets>,
    #[prost(message, optional, tag = "2")]
    pub sec_check: Option<NtLoginSecCheck>,
    #[prost(message, optional, tag = "3")]
    pub sec_protect: Option<NtLoginSecProtect>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginSecCheck {
    #[prost(string, optional, tag = "3")]
    pub iframe_url: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NtLoginSecProtect {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub new_device_check_sig: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub unusual_device_check_sig: Option<Vec<u8>>,
    #[prost(string, optional, tag = "3")]
    pub unusual_device_qr_sig: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub uin_token: Option<String>,
}

/// `NTLoginTickets`：a2/d2/d2key 就在这里。
#[derive(Clone, PartialEq, Message)]
pub struct NtLoginTickets {
    #[prost(bytes = "vec", optional, tag = "3")]
    pub a1: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub a2: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub d2: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub d2_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub auth_code: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub nopicsig: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "14")]
    pub a1_key: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "15")]
    pub a1_seq: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 锁字段号：任何一个 tag 写错都会立刻在这里炸。
    #[test]
    fn easy_login_req_body_a1_is_tag1() {
        let body = NtLoginEasyLoginReqBody {
            a1: Some(vec![0xAA, 0xBB]),
        };
        assert_eq!(body.encode_to_vec(), vec![0x0a, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn forward_request_tags_match_lagrange() {
        let fwd = NtLoginForwardRequest {
            session_ticket: Some(vec![0x01]),
            buffer: Some(vec![0x02]),
            r#type: Some(1),
            sec_buffer: None,
        };
        // ticket=1(0a) · buffer=3(1a) · type=4(20)；sec_buffer=5 不写。
        assert_eq!(
            fwd.encode_to_vec(),
            vec![0x0a, 0x01, 0x01, 0x1a, 0x01, 0x02, 0x20, 0x01]
        );
    }

    #[test]
    fn tickets_a2_d2_d2key_tags() {
        let tickets = NtLoginTickets {
            a2: Some(vec![0x09]),
            d2: Some(vec![0x08]),
            d2_key: Some(vec![0x07; 16]),
            ..Default::default()
        };
        let bytes = tickets.encode_to_vec();
        // a2=4(0x22) · d2=5(0x2a) · d2key=6(0x32)
        assert_eq!(bytes[0], 0x22);
        assert_eq!(&bytes[..3], &[0x22, 0x01, 0x09]);
        assert_eq!(&bytes[3..6], &[0x2a, 0x01, 0x08]);
        assert_eq!(&bytes[6..8], &[0x32, 0x10]);
    }

    #[test]
    fn key_exchange_request_tags() {
        let req = KeyExchangeRequest {
            public_key: vec![0x04; 65],
            r#type: 1,
            secret: vec![0x01, 0x02],
            timestamp: 0x01020304,
            verify_hash: vec![0xEE; 5],
        };
        let bytes = req.encode_to_vec();
        // 1(0a, len 65) · 2(10, 1) · 3(1a, len 2) · 4(20, varint) · 5(2a, len 5)
        assert_eq!(&bytes[..2], &[0x0a, 65]);
        assert_eq!(&bytes[67..69], &[0x10, 0x01]);
        assert_eq!(&bytes[69..72], &[0x1a, 0x02, 0x01]);
        assert_eq!(bytes[73], 0x20); // timestamp = tag4
        assert_eq!(&bytes[74..78], &[0x84, 0x86, 0x88, 0x08]); // 0x01020304 的 varint
        assert_eq!(*bytes.last().unwrap(), 0xEE);
    }

    #[test]
    fn unset_option_fields_are_omitted() {
        // IgnoreDefaultFields 语义：None 不写（例如 PC 路径不写 SecBuffer/Qua）。
        let head = NtLoginAppInfo {
            version: Some("7.2.7-arch1-1".into()),
            app_id: Some(1600001615),
            app_name: Some("com.tencent.qq".into()),
            client_a1_version: None,
            qua: None,
        };
        let bytes = head.encode_to_vec();
        // 只有 tag1/2/3；tag4(0x20) 与 tag5(0x2a) 不出现。
        assert!(bytes.contains(&0x0a));
        assert!(bytes.contains(&0x10));
        assert!(bytes.contains(&0x1a));
        assert!(!bytes[2..].contains(&0x20), "client_a1_version 不该被写");
        assert!(!bytes[2..].contains(&0x2a), "qua 不该被写");
    }
}
