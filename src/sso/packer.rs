//! SSO 协议 12/13 的组包与解包。
//!
//! **布局以真实抓包为准**（qqshark `/tmp/cde2.log` + `Heartbeat.Alive` 帧，2026-10-07），
//! 与 Lagrange 有出入的地方按抓包改（见各常量/注释）。两层结构（由内往外）：
//!
//! ```text
//! [SSO 层 12]  sequence · subAppId · 2052 · NT_HEAD_PREAMBLE · a2 · command · cookies ·
//!              guid · "" · ""(version) · reserved(proto)
//! [SSO 层 13]  command · cookies · reserved(proto)
//! [Service 12] protocol(12) · et · d2 · 00 · uin · cipher
//! [Service 13] protocol(13) · et · sequence · 00 · uin · cipher
//! ```
//!
//! 协议 12 = `D2Auth`（带 a2/guid/保留字段），协议 13 = `Simple`（更精简）。
//!
//! 实测报文例子：`build_sso_layer12` 能逐字节复现抓到的 `OidbSvcTrpcTcp.0xcde_2`
//! 336 字节头；`build_packet(Simple, …)` 能逐字节复现抓到的 `Heartbeat.Alive` 153
//! 字节帧（见本模块 tests 里的 `proto12_head_reproduces_captured_cde2` /
//! `proto13_frame_reproduces_captured_heartbeat`）。

use anyhow::{Context, Result};
use prost::Message;

use super::packet::{Reader, Writer, PREFIX_I16, PREFIX_I32};
use super::proto::{SsoReserveFields, SsoSecureInfo, TransInfoEntry};
use super::tea;

/// 请求类型，同时也是 service 层里的 `protocol` 字段。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestType {
    /// 12：D2Auth。
    D2Auth,
    /// 13：Simple。
    Simple,
}

impl RequestType {
    fn code(self) -> i32 {
        match self {
            RequestType::D2Auth => 12,
            RequestType::Simple => 13,
        }
    }
}

/// 包体加密方式（`EncryptType`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncryptType {
    /// 0x00：不加密。
    NoEncrypt,
    /// 0x01：用 d2key 加密。
    EncryptD2Key,
    /// 0x02：用全零 key 加密。
    EncryptEmpty,
}

impl EncryptType {
    fn code(self) -> u8 {
        match self {
            EncryptType::NoEncrypt => 0x00,
            EncryptType::EncryptD2Key => 0x01,
            EncryptType::EncryptEmpty => 0x02,
        }
    }

    fn from_code(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(EncryptType::NoEncrypt),
            0x01 => Ok(EncryptType::EncryptD2Key),
            0x02 => Ok(EncryptType::EncryptEmpty),
            other => anyhow::bail!("未知的 EncryptType: 0x{other:02x}"),
        }
    }
}

const EMPTY_D2_KEY: [u8; 16] = [0u8; 16];

/// 一次 SSO 会话的物料（从内存/离线 guid 读到的密钥 + 应用信息）。
///
/// `trace_parent` / `client_conn_seq` 留了显式注入点，便于测试逐字节复现抓包；
/// `None` 时前者随机生成、后者取当前 unix 秒。
pub struct SsoContext<'a> {
    /// 账号 UIN 的十进制字符串，如 `1707889225`。
    pub uin: &'a str,
    /// a2（tgt），原始字节。
    pub a2: &'a [u8],
    /// d2，原始字节。
    pub d2: &'a [u8],
    /// d2key，必须 16 字节。
    pub d2_key: &'a [u8],
    /// 设备 guid 的小写 hex 字符串。
    pub guid: &'a str,
    /// 账号 uid。
    pub uid: &'a str,
    /// `subAppId`（NT 应用标识）；抓包实测 PC 端为 `537391664`。
    pub sub_app_id: i32,
    /// reserved tag 15（`trace_parent`）。`None` = 按抓包格式随机生成。
    pub trace_parent: Option<String>,
    /// reserved tag 23 里 `client_conn_seq` 的值。`None` = 当前 unix 秒。
    pub client_conn_seq: Option<String>,
    /// SSO 头里的客户端版本字段（`AppInfo.CurrentVersion`）。`None` = 写空串。
    pub client_version: Option<String>,
}

/// `2052` 之后那 12 字节。抓包实测 `00 ×10 03 00`（Lagrange 写的是 `02 00 ×11`）。
const NT_HEAD_PREAMBLE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x00];

/// reserved tag 26（`nt_core_version`）的实测值。
const NT_CORE_VERSION: u32 = 101;

/// 生成 `SsoReserveFields` 的 `TraceParent`。
///
/// 格式取真实抓包：`00-<32hex>-<16hex>-00`（Lagrange 用的是 `01-…-01`）。
fn trace_parent() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut state = seed | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        HEX[(state & 0xF) as usize]
    };
    let mut out = String::with_capacity(55);
    out.push_str("00-");
    for _ in 0..32 {
        out.push(next() as char);
    }
    out.push('-');
    for _ in 0..16 {
        out.push(next() as char);
    }
    out.push_str("-00");
    out
}

pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 组 reserved 字段（tag 见 `proto.rs`）。
///
/// `with_trace` 控制 tag 13/15：抓包里 proto 12 带 `env(13)` + `trace_parent(15)`，
/// proto 13 只带 `12/16/23/26`。
fn reserved_fields(
    ctx: &SsoContext<'_>,
    sec_info: Option<&SsoSecureInfo>,
    with_trace: bool,
) -> SsoReserveFields {
    let mut fields = SsoReserveFields {
        guid: Some(ctx.guid.to_string()),
        // 空 uid 不写 tag16：真机 transemp 的 reserved 里没有 tag16（login 命令的 uid
        // 非空、照常写）。空串写成 `82 01 00` 是个多余的字段。
        uid: if ctx.uid.is_empty() {
            None
        } else {
            Some(ctx.uid.to_string())
        },
        trans_info: vec![TransInfoEntry {
            key: "client_conn_seq".to_string(),
            value: ctx
                .client_conn_seq
                .clone()
                .unwrap_or_else(|| now_unix_secs().to_string()),
        }],
        nt_core_version: Some(NT_CORE_VERSION),
        sec_info: sec_info.cloned(),
        ..Default::default()
    };
    if with_trace {
        fields.env = Some(vec![0x00]);
        fields.trace_parent = Some(ctx.trace_parent.clone().unwrap_or_else(trace_parent));
    }
    fields
}

/// SSO 层编码（协议 12）。
pub fn build_sso_layer12(
    ctx: &SsoContext<'_>,
    command: &str,
    sequence: i32,
    data: &[u8],
    sec_info: Option<&SsoSecureInfo>,
) -> Vec<u8> {
    let mut head = Writer::new();
    head.i32v(sequence);
    head.i32v(ctx.sub_app_id);
    head.i32v(2052);
    head.raw(&NT_HEAD_PREAMBLE);
    head.prefixed(ctx.a2, PREFIX_I32);
    head.prefixed_str(command, PREFIX_I32);
    head.prefixed(&[], PREFIX_I32); // message_cookies
    head.prefixed_str(ctx.guid, PREFIX_I32);
    head.prefixed(&[], PREFIX_I32);
    // 客户端版本字段：传了 `client_version` 就写真实版本（Lagrange 行为，
    // `AppInfo.CurrentVersion`）；没传写空串（早期抓包形态）。
    head.prefixed_str(ctx.client_version.as_deref().unwrap_or(""), PREFIX_I16);
    let fields = reserved_fields(ctx, sec_info, true).encode_to_vec();
    head.prefixed(&fields, PREFIX_I32);

    let mut out = Writer::new();
    out.prefixed(head.as_slice(), PREFIX_I32);
    out.prefixed(data, PREFIX_I32);
    out.into_vec()
}

/// SSO 层编码（协议 13）。
pub fn build_sso_layer13(
    ctx: &SsoContext<'_>,
    command: &str,
    data: &[u8],
    sec_info: Option<&SsoSecureInfo>,
) -> Vec<u8> {
    let mut head = Writer::new();
    head.prefixed_str(command, PREFIX_I32);
    head.prefixed(&[], PREFIX_I32); // message_cookies
    let fields = reserved_fields(ctx, sec_info, false).encode_to_vec();
    head.prefixed(&fields, PREFIX_I32);

    let mut out = Writer::new();
    out.prefixed(head.as_slice(), PREFIX_I32);
    out.prefixed(data, PREFIX_I32);
    out.into_vec()
}

fn encrypt_body(ctx: &SsoContext<'_>, body: &[u8], encrypt: EncryptType) -> Result<Vec<u8>> {
    match encrypt {
        EncryptType::NoEncrypt => Ok(body.to_vec()),
        EncryptType::EncryptEmpty => Ok(tea::encrypt(body, &EMPTY_D2_KEY)),
        EncryptType::EncryptD2Key => {
            if ctx.d2_key.len() != 16 {
                anyhow::bail!("d2key 必须是 16 字节，实际 {}", ctx.d2_key.len());
            }
            Ok(tea::encrypt(body, ctx.d2_key))
        }
    }
}

/// Service 层封装（协议 12）。
pub fn build_service_layer12(
    ctx: &SsoContext<'_>,
    sso_bytes: &[u8],
    encrypt: EncryptType,
) -> Result<Vec<u8>> {
    let cipher = encrypt_body(ctx, sso_bytes, encrypt)?;

    let mut w = Writer::new();
    w.begin_barrier(PREFIX_I32);
    w.i32v(RequestType::D2Auth.code());
    w.u8v(encrypt.code());
    if encrypt == EncryptType::EncryptD2Key {
        w.prefixed(ctx.d2, PREFIX_I32);
    } else {
        w.i32v(4);
    }
    w.u8v(0);
    w.prefixed_str(ctx.uin, PREFIX_I32);
    w.raw(&cipher);
    w.end_barrier();
    Ok(w.into_vec())
}

/// Service 层封装（协议 13）。
pub fn build_service_layer13(
    ctx: &SsoContext<'_>,
    sequence: i32,
    sso_bytes: &[u8],
    encrypt: EncryptType,
) -> Result<Vec<u8>> {
    let cipher = encrypt_body(ctx, sso_bytes, encrypt)?;

    let mut w = Writer::new();
    w.begin_barrier(PREFIX_I32);
    w.i32v(RequestType::Simple.code());
    w.u8v(encrypt.code());
    w.i32v(sequence);
    w.u8v(0);
    w.prefixed_str(ctx.uin, PREFIX_I32);
    w.raw(&cipher);
    w.end_barrier();
    Ok(w.into_vec())
}

/// 一步组完整包：SSO 层 + Service 层。
pub fn build_packet(
    ctx: &SsoContext<'_>,
    request_type: RequestType,
    command: &str,
    sequence: i32,
    data: &[u8],
    sec_info: Option<&SsoSecureInfo>,
    encrypt: EncryptType,
) -> Result<Vec<u8>> {
    match request_type {
        RequestType::D2Auth => {
            let sso = build_sso_layer12(ctx, command, sequence, data, sec_info);
            build_service_layer12(ctx, &sso, encrypt)
        }
        RequestType::Simple => {
            let sso = build_sso_layer13(ctx, command, data, sec_info);
            build_service_layer13(ctx, sequence, &sso, encrypt)
        }
    }
}

/// 收到的 SSO 应答（解出 service 层之后）。
#[derive(Clone, Debug)]
pub struct SsoResponse {
    pub command: String,
    pub sequence: i32,
    pub ret_code: i32,
    pub extra: String,
    pub payload: Vec<u8>,
}

/// 解开 service 层，返回其中的 SSO 层字节。
pub fn parse_service_layer(ctx: &SsoContext<'_>, input: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(input);
    let _total_len = r.u32v()?;
    let protocol = r.i32v()?;
    let auth_flag = r.u8v()?;
    let _dummy = r.u8v()?;
    let _uin = r.prefixed_str(PREFIX_I32)?;
    let body = r.rest();

    let encrypt = EncryptType::from_code(auth_flag)?;
    match encrypt {
        EncryptType::NoEncrypt => Ok(body.to_vec()),
        EncryptType::EncryptEmpty => tea::decrypt(body, &EMPTY_D2_KEY),
        EncryptType::EncryptD2Key => tea::decrypt(body, ctx.d2_key),
    }
    .with_context(|| format!("解密 service 层包体失败（protocol={protocol}）"))
}

/// 解开 SSO 层。
pub fn parse_sso_layer(data: &[u8]) -> Result<SsoResponse> {
    let mut outer = Reader::new(data);
    let head = outer.prefixed(PREFIX_I32)?;
    let body = outer.prefixed(PREFIX_I32)?;

    let mut r = Reader::new(head);
    let sequence = r.i32v()?;
    let ret_code = r.i32v()?;
    let extra = r.prefixed_str(PREFIX_I32)?;
    let command = r.prefixed_str(PREFIX_I32)?;
    let _cookies = r.prefixed(PREFIX_I32)?;
    let data_flag = r.i32v()?;
    let _reserved = r.prefixed(PREFIX_I32)?;

    // dataFlag: 0/4 = 原样，1 = 压缩（zlib/deflate）。压缩解压留待需要时接入。
    if data_flag == 1 {
        anyhow::bail!("SSO 应答体是压缩的（dataFlag=1），暂未接入解压");
    }

    Ok(SsoResponse {
        command,
        sequence,
        ret_code,
        extra,
        payload: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(a2: &'a [u8], d2: &'a [u8], d2_key: &'a [u8]) -> SsoContext<'a> {
        SsoContext {
            uin: "1707889225",
            a2,
            d2,
            d2_key,
            guid: "917acf0aae3bc80bc1f7780942b7e050",
            uid: "u_test",
            sub_app_id: 537391664,
            trace_parent: None,
            client_conn_seq: None,
            client_version: None,
        }
    }

    #[test]
    fn trace_parent_has_expected_shape() {
        let t = trace_parent();
        assert_eq!(t.len(), 55);
        assert!(t.starts_with("00-"));
        assert!(t.ends_with("-00"));
        let mid: Vec<&str> = t.split('-').collect();
        assert_eq!(mid.len(), 4);
        assert_eq!(mid[1].len(), 32);
        assert_eq!(mid[2].len(), 16);
        assert!(mid[1].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(mid[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn protocol12_service_layer_shape_is_parseable() {
        let a2 = vec![0x11u8; 16];
        let d2 = vec![0x22u8; 8];
        let d2_key = [0x33u8; 16];
        let c = ctx(&a2, &d2, &d2_key);

        let packet = build_packet(
            &c,
            RequestType::D2Auth,
            "test.cmd",
            12345,
            b"payload",
            None,
            EncryptType::EncryptD2Key,
        )
        .unwrap();

        let mut r = Reader::new(&packet);
        let _len = r.u32v().unwrap();
        assert_eq!(r.i32v().unwrap(), 12);
        assert_eq!(r.u8v().unwrap(), EncryptType::EncryptD2Key.code());
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), &d2[..]);
        assert_eq!(r.u8v().unwrap(), 0);
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), "1707889225");

        // service 层头读完，剩下就是密文：解开后核对 SSO 请求层布局。
        let cipher = r.rest();
        let sso = tea::decrypt(cipher, &d2_key).unwrap();
        let mut o = Reader::new(&sso);
        let head = o.prefixed(PREFIX_I32).unwrap();
        assert_eq!(o.prefixed(PREFIX_I32).unwrap(), b"payload");
        let mut hr = Reader::new(head);
        assert_eq!(hr.i32v().unwrap(), 12345, "sequence");
        assert_eq!(hr.i32v().unwrap(), 537391664, "subAppId");
        assert_eq!(hr.i32v().unwrap(), 2052);
    }

    /// 应答（service 层）格式：length · protocol · authFlag · dummy · uin · cipher。
    /// 应答的 SSO 头是 `sequence · retCode · extra · command · cookies · dataFlag · reserved`。
    #[test]
    fn parses_a_service_layer_reply() {
        let d2_key = [0x44u8; 16];
        let c = ctx(&[0u8; 4], &[0u8; 4], &d2_key);

        let mut head = Writer::new();
        head.i32v(9); // sequence
        head.i32v(0); // retCode
        head.prefixed_str("", PREFIX_I32); // extra
        head.prefixed_str("evt.cmd", PREFIX_I32);
        head.prefixed(&[], PREFIX_I32); // cookies
        head.i32v(0); // dataFlag：0 = 原样
        head.prefixed(&[], PREFIX_I32); // reserved
        let mut sso_w = Writer::new();
        sso_w.prefixed(head.as_slice(), PREFIX_I32);
        sso_w.prefixed(b"resp", PREFIX_I32);
        let sso = sso_w.into_vec();

        let cipher = tea::encrypt(&sso, &d2_key);
        let mut w = Writer::new();
        w.begin_barrier(PREFIX_I32);
        w.i32v(12);
        w.u8v(EncryptType::EncryptD2Key.code());
        w.u8v(0);
        w.prefixed_str("1707889225", PREFIX_I32);
        w.raw(&cipher);
        w.end_barrier();

        let sso = parse_service_layer(&c, w.as_slice()).unwrap();
        let resp = parse_sso_layer(&sso).unwrap();
        assert_eq!(resp.command, "evt.cmd");
        assert_eq!(resp.sequence, 9);
        assert_eq!(resp.payload, b"resp");
    }

    #[test]
    fn protocol12_uses_empty_d2_placeholder_when_not_d2key() {
        let c = ctx(&[1u8; 4], &[2u8; 4], &[3u8; 16]);
        let packet = build_packet(
            &c,
            RequestType::D2Auth,
            "c",
            1,
            b"x",
            None,
            EncryptType::EncryptEmpty,
        )
        .unwrap();
        let mut r = Reader::new(&packet);
        let _ = r.u32v().unwrap();
        assert_eq!(r.i32v().unwrap(), 12);
        assert_eq!(r.u8v().unwrap(), EncryptType::EncryptEmpty.code());
        assert_eq!(r.i32v().unwrap(), 4, "非 D2Key 时写常量 4");
    }

    #[test]
    fn protocol13_layout_and_round_trip() {
        let c = ctx(&[1u8; 4], &[2u8; 4], &[3u8; 16]);
        let packet = build_packet(
            &c,
            RequestType::Simple,
            "cmd13",
            777,
            b"body13",
            None,
            EncryptType::EncryptEmpty,
        )
        .unwrap();

        let mut r = Reader::new(&packet);
        let _ = r.u32v().unwrap();
        assert_eq!(r.i32v().unwrap(), 13);
        assert_eq!(r.u8v().unwrap(), EncryptType::EncryptEmpty.code());
        assert_eq!(r.i32v().unwrap(), 777);
        assert_eq!(r.u8v().unwrap(), 0, "dummy");
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), "1707889225");

        let cipher = r.rest();
        let sso = tea::decrypt(cipher, &[0u8; 16]).unwrap();
        let mut o = Reader::new(&sso);
        let head = o.prefixed(PREFIX_I32).unwrap();
        assert_eq!(o.prefixed(PREFIX_I32).unwrap(), b"body13");
        let mut hr = Reader::new(head);
        assert_eq!(hr.prefixed_str(PREFIX_I32).unwrap(), "cmd13");
    }

    #[test]
    fn sso_layer12_carries_a2_guid_and_reserved_fields() {
        let a2 = vec![0xABu8; 20];
        let c = ctx(&a2, &[0u8; 4], &[0u8; 16]);
        let sso = build_sso_layer12(&c, "cmd12", 42, b"data", None);

        let mut outer = Reader::new(&sso);
        let head = outer.prefixed(PREFIX_I32).unwrap();
        let body = outer.prefixed(PREFIX_I32).unwrap();
        assert_eq!(body, b"data");

        let mut r = Reader::new(head);
        assert_eq!(r.i32v().unwrap(), 42);
        assert_eq!(r.i32v().unwrap(), 537391664);
        assert_eq!(r.i32v().unwrap(), 2052);
        assert_eq!(r.bytes(12).unwrap(), NT_HEAD_PREAMBLE);
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), &a2[..]);
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), "cmd12");
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), b"");
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), c.guid);
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), b"");
        assert_eq!(r.prefixed_str(PREFIX_I16).unwrap(), "");
        let fields = SsoReserveFields::decode(r.prefixed(PREFIX_I32).unwrap()).unwrap();
        assert_eq!(fields.guid.as_deref(), Some(c.guid));
        assert_eq!(fields.uid.as_deref(), Some("u_test"));
        assert_eq!(fields.nt_core_version, Some(NT_CORE_VERSION));
        assert_eq!(fields.trans_info[0].key, "client_conn_seq");
        assert!(fields.sec_info.is_none());
    }

    #[test]
    fn sec_info_lands_in_reserved_fields() {
        let c = ctx(&[1u8; 4], &[2u8; 4], &[3u8; 16]);
        let sec = SsoSecureInfo {
            sec_sign: vec![9, 9],
            sec_token: vec![7],
            sec_extra: vec![],
        };
        let sso = build_sso_layer12(&c, "cmd", 1, b"d", Some(&sec));
        let mut outer = Reader::new(&sso);
        let head = outer.prefixed(PREFIX_I32).unwrap();
        let mut r = Reader::new(head);
        let _ = r.i32v().unwrap();
        let _ = r.i32v().unwrap();
        let _ = r.i32v().unwrap();
        let _ = r.bytes(12).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap();
        let _ = r.prefixed(PREFIX_I16).unwrap();
        let fields = SsoReserveFields::decode(r.prefixed(PREFIX_I32).unwrap()).unwrap();
        assert_eq!(fields.sec_info, Some(sec));
    }

    // ── 真实抓包向量（qqshark，2026-10-07）────────────────────────────────
    // `OidbSvcTrpcTcp.0xcde_2`（proto 12，已解密明文）与 `Heartbeat.Alive`
    //（proto 13，未加密帧）。用来钉死「本模块组出的包 == QQ 实际发的字节」。
    const CDE2_SEQ: i32 = 5_959_159;
    const CDE2_SUB_APP: i32 = 537_391_664;
    const CDE2_TRACE: &str = "00-d68e50b431c9357c20851ee65c9a3563-049736f21f480309-00";
    const CDE2_GUID: &str = "917acf0aae3bc80bc1f7780942b7e050";
    const CDE2_UID: &str = "u_mGIBTBW7gF4Wocw8zapc6w";
    const CDE2_CONN_SEQ: &str = "1791299538";
    const CDE2_A2_HEX: &str = "7e5cf68581a06af2c8fefe46d238ee5c394bf752ec431414eb9b881bdbdc9acf3e024afa68f8f9ac92f603fc33653e36e1ea89af6c8fa9a07a8e7206a145276f3eaf15fc86b0a876";
    /// `0xcde_2` 请求头 336 字节（含 4 字节头长前缀）。
    const CDE2_HEAD_HEX: &str = "00000150005aedf72007f230000008040000000000000000000003000000004c7e5cf68581a06af2c8fefe46d238ee5c394bf752ec431414eb9b881bdbdc9acf3e024afa68f8f9ac92f603fc33653e36e1ea89af6c8fa9a07a8e7206a145276f3eaf15fc86b0a8760000001a4f696462537663547270635463702e30786364655f3200000004000000243931376163663061616533626338306263316637373830393432623765303530000000040002000000a0622039313761636630616165336263383062633166373738303934326237653035306a01007a3730302d64363865353062343331633933353763323038353165653635633961333536332d303439373336663231663438303330392d3030820118755f6d47494254425737674634576f6377387a6170633677ba011d0a0f636c69656e745f636f6e6e5f736571120a31373931323939353338d00165";
    /// `Heartbeat.Alive` proto 13 未加密帧 153 字节。
    const HEARTBEAT_TX_HEX: &str = "000000990000000d00005aee1500000000040000007f000000134865617274626561742e416c697665000000040000006462203931376163663061616533626338306263316637373830393432623765303530820118755f6d47494254425737674634576f6377387a6170633677ba011d0a0f636c69656e745f636f6e6e5f736571120a31373931323939353338d001650000000800000004";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn capture_ctx<'a>(a2: &'a [u8], uin: &'a str) -> SsoContext<'a> {
        SsoContext {
            uin,
            a2,
            d2: &[],
            d2_key: &[0u8; 16],
            guid: CDE2_GUID,
            uid: CDE2_UID,
            sub_app_id: CDE2_SUB_APP,
            trace_parent: Some(CDE2_TRACE.to_string()),
            client_conn_seq: Some(CDE2_CONN_SEQ.to_string()),
            client_version: None,
        }
    }

    /// 用抓到的物料重新组 proto 12 头，必须与抓包逐字节相同。
    #[test]
    fn proto12_head_reproduces_captured_cde2() {
        let a2 = unhex(CDE2_A2_HEX);
        let ctx = capture_ctx(&a2, "1707889225");
        let sso = build_sso_layer12(&ctx, "OidbSvcTrpcTcp.0xcde_2", CDE2_SEQ, b"", None);
        let head = unhex(CDE2_HEAD_HEX);
        assert_eq!(head.len(), 336);
        assert_eq!(&sso[..336], &head[..], "SSO 头 != 抓包");
    }

    /// proto 13 整帧（service + SSO）必须与抓包逐字节相同。
    #[test]
    fn proto13_frame_reproduces_captured_heartbeat() {
        let ctx = capture_ctx(&[], "");
        let frame = build_packet(
            &ctx,
            RequestType::Simple,
            "Heartbeat.Alive",
            5_959_189,
            &[0, 0, 0, 4],
            None,
            EncryptType::NoEncrypt,
        )
        .unwrap();
        assert_eq!(frame, unhex(HEARTBEAT_TX_HEX));
    }

    // 第二条抓包（/tmp/capture.log）：一条**带签名**的 `MessageSvc.PbSendMsg`。
    const SIGN_MSG_SEQ: i32 = 5_959_337;
    const SIGN_MSG_TRACE: &str = "00-3fcdd631819a99d387b12a0ec745ffc4-75f9ffc8199c7e19-00";
    const SIGN_MSG_HEAD_HEX: &str = "000001b0005aeea92007f230000008040000000000000000000003000000004c7e5cf68581a06af2c8fefe46d238ee5c394bf752ec431414eb9b881bdbdc9acf3e024afa68f8f9ac92f603fc33653e36e1ea89af6c8fa9a07a8e7206a145276f3eaf15fc86b0a876000000184d6573736167655376632e506253656e644d73670000000400000024393137616366306161653362633830626331663737383039343262376530353000000004000200000102622039313761636630616165336263383062633166373738303934326237653035306a01007a3730302d33666364643633313831396139396433383762313261306563373435666663342d373566396666633831393963376531392d3030820118755f6d47494254425737674634576f6377387a6170633677ba011d0a0f636c69656e745f636f6e6e5f736571120a31373931323939353338c2015f0a30d12af83db781eaa956143022cf5a92308378c425e5a9436120b33d849600b219bec1b1f23c52e65afe4fd76835caf0cd120c396643585a356767667645411a1d121b56315f4c4e585f4e515f332e322e33345f35333634345f47575f42d00165";
    /// 抓包里 tag 24 的三段：sign=48B、token=12B、extra=29B。
    const SIGN_HEX: &str = "d12af83db781eaa956143022cf5a92308378c425e5a9436120b33d849600b219bec1b1f23c52e65afe4fd76835caf0cd";
    const TOKEN_HEX: &str = "396643585a35676766764541";
    const EXTRA_HEX: &str = "121b56315f4c4e585f4e515f332e322e33345f35333634345f47575f42";

    /// 带签名的 proto 12 头也必须与抓包逐字节相同。
    #[test]
    fn proto12_head_reproduces_captured_signed_send_msg() {
        let a2 = unhex(CDE2_A2_HEX);
        let mut ctx = capture_ctx(&a2, "1707889225");
        ctx.trace_parent = Some(SIGN_MSG_TRACE.to_string());
        let sec = SsoSecureInfo {
            sec_sign: unhex(SIGN_HEX),
            sec_token: unhex(TOKEN_HEX),
            sec_extra: unhex(EXTRA_HEX),
        };
        let sso = build_sso_layer12(&ctx, "MessageSvc.PbSendMsg", SIGN_MSG_SEQ, b"", Some(&sec));
        let head = unhex(SIGN_MSG_HEAD_HEX);
        assert_eq!(head.len(), 432);
        assert_eq!(&sso[..432], &head[..], "带签名 SSO 头 != 抓包");
    }

    /// 回答「0xcde_2 有没有签名」：抓包头 reserved 里没有 tag 24，故没有签名。
    #[test]
    fn captured_cde2_carries_no_sec_sign() {
        let head = unhex(CDE2_HEAD_HEX);
        let mut r = Reader::new(&head);
        let _headlen = r.u32v().unwrap();
        let _seq = r.i32v().unwrap();
        let _sub = r.i32v().unwrap();
        let _c = r.i32v().unwrap();
        let _ = r.bytes(12).unwrap();
        let _ = r.prefixed(PREFIX_I32).unwrap(); // a2
        let _ = r.prefixed(PREFIX_I32).unwrap(); // command
        let _ = r.prefixed(PREFIX_I32).unwrap(); // cookies
        let _ = r.prefixed(PREFIX_I32).unwrap(); // guid
        let _ = r.prefixed(PREFIX_I32).unwrap(); // empty
        let _ = r.prefixed(PREFIX_I16).unwrap(); // version
        let fields = SsoReserveFields::decode(r.prefixed(PREFIX_I32).unwrap()).unwrap();
        assert!(
            fields.sec_info.is_none(),
            "0xcde_2 抓包里不应有 sec_info（签名）"
        );
        assert_eq!(fields.guid.as_deref(), Some(CDE2_GUID));
        assert_eq!(fields.uid.as_deref(), Some(CDE2_UID));
        assert_eq!(fields.nt_core_version, Some(101));
        assert_eq!(fields.env.as_deref(), Some(&[0x00u8][..]));
        assert_eq!(fields.trace_parent.as_deref(), Some(CDE2_TRACE));
        assert_eq!(fields.trans_info.len(), 1);
        assert_eq!(fields.trans_info[0].key, "client_conn_seq");
        assert_eq!(fields.trans_info[0].value, CDE2_CONN_SEQ);
    }
}
