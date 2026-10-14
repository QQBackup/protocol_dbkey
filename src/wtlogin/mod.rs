//! PC 端 wtlogin **快速登录（EasyLogin）**：只用本地 `login.db` 的 a1 + 设备 guid，
//! 直连登录服务器换 a2/d2/d2key，随后在同一条连接上用 `0xcde_2` 取 dbkey。
//!
//! 流程（对齐 nt_helper `src/wtlogin`，`../Lagrange` 的 PC 分支）：
//! 1. `trpc.login.ecdh.EcdhService.SsoKeyExchange`（协议 12 / EncryptEmpty）：
//!    P-256 ECDH 握手，换出 `SessionTicket` + `SessionKey`；
//! 2. `trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin`：外层 `NTLoginForwardRequest`，
//!    内层 `NTLoginCommon{ A1 }` 用 `SessionKey` 做 AES-GCM；回包 `Tickets` 里是
//!    a2/d2/d2key；
//! 3. `OidbSvcTrpcTcp.0xcde_2`（EncryptD2Key，不签名）：用 key_meta 换 dbkey。
//!
//! 本工具**只走快登**：没有 a1 / 命中异常设备 / 任一步报错一律直接失败退出，
//! 不做二维码路径，也不做异常设备确认回退。

pub mod crypto;
pub mod proto;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::sign::call::Signer;
use crate::sso::packer::{self, EncryptType, RequestType, SsoResponse};
use crate::sso::proto::SsoSecureInfo;
use crate::sso::session::SsoSession;

use crypto::P256KeyPair;
use proto::*;

/// 登录服务器（与 ssoclient 同一台）。
const LOGIN_SERVER: &str = "msfwifi.3g.qq.com:8080";
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const FLOW_TIMEOUT: Duration = Duration::from_secs(45);

const KEY_EXCHANGE_CMD: &str = "trpc.login.ecdh.EcdhService.SsoKeyExchange";
const EASY_LOGIN_CMD: &str = "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin";

/// 服务端 P-256 公钥（Lagrange `KeyExchangeService.ServerPublicKey`）。
const SERVER_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x9D, 0x14, 0x23, 0x33, 0x27, 0x35, 0x98, 0x0E, 0xDA, 0xBE, 0x7E, 0x9E, 0xA4, 0x51,
    0xB3, 0x39, 0x5B, 0x6F, 0x35, 0x25, 0x0D, 0xB8, 0xFC, 0x56, 0xF2, 0x58, 0x89, 0xF6, 0x28,
    0xCB, 0xAE, 0x3E, 0x8E, 0x73, 0x07, 0x79, 0x14, 0x07, 0x1E, 0xEE, 0xBC, 0x10, 0x8F, 0x4E,
    0x01, 0x70, 0x05, 0x77, 0x92, 0xBB, 0x17, 0xAA, 0x30, 0x3A, 0xF6, 0x52, 0x31, 0x3D, 0x17,
    0xC1, 0xAC, 0x81, 0x5E, 0x79,
];

/// `verifyHash` 的 AES-GCM 密钥（Lagrange `VerifyHashKey`）。
const VERIFY_HASH_KEY: [u8; 32] = [
    0xe2, 0x73, 0x3b, 0xf4, 0x03, 0x14, 0x99, 0x13, 0xcb, 0xf8, 0x0c, 0x7a, 0x95, 0x16, 0x8b,
    0xd4, 0xca, 0x69, 0x35, 0xee, 0x53, 0xcd, 0x39, 0x76, 0x4b, 0xee, 0xbe, 0x2e, 0x00, 0x7e,
    0x3a, 0xee,
];

/// 异常设备（`LOGIN_ERROR_UNUSUAL_DEVICE`）：需手机确认 / 扫码，本工具不回退。
const RET_UNUSUAL_DEVICE: u64 = 140022011;

/// 快登入参。
pub struct QuickLoginOptions {
    pub uin: String,
    pub a1: Vec<u8>,
    pub guid: String,
    pub app_id: i32,
    pub sub_app_id: i32,
    pub os: String,
    pub platform: i32,
    pub device_name: String,
    pub kernel_version: String,
    pub app_name: Option<String>,
    pub qua: Option<String>,
    pub client_version: Option<String>,
    pub wrapper_path: Option<String>,
    pub uid: Option<String>,
    /// `nt_msg.db` 头 `0x2f..0xaf` 的 128 字节 key_meta（dbSalt）。
    pub key_meta: Option<String>,
}

/// 快登成功后的会话物料。
pub struct QuickLoginResult {
    pub uin: String,
    pub uid: Option<String>,
    pub guid: String,
    pub a2: Vec<u8>,
    pub d2: Vec<u8>,
    pub d2_key: Vec<u8>,
    pub db_key: String,
}

fn with_client_version(session: SsoSession, client_version: Option<&str>) -> SsoSession {
    match client_version {
        Some(v) if !v.is_empty() => session.with_client_version(v.to_string()),
        _ => session,
    }
}

/// 同步执行一次快速登录（含 0xcde_2 取 dbkey）。
pub fn quick_login_blocking(opts: &QuickLoginOptions) -> Result<QuickLoginResult> {
    let deadline = Instant::now() + FLOW_TIMEOUT;

    if opts.a1.is_empty() {
        bail!("a1 为空：需要先在 QQ 客户端登录一次以缓存 a1");
    }
    let guid_bytes = hex::decode(&opts.guid).context("guid 不是合法 hex")?;
    if guid_bytes.len() != 16 {
        bail!("guid 必须是 16 字节（32 位 hex），实际 {} 字节", guid_bytes.len());
    }
    let key_meta = opts
        .key_meta
        .as_deref()
        .ok_or_else(|| anyhow!("缺少 key_meta：无法换取 dbkey（请确认 nt_msg.db 存在且可读）"))?;
    let app_name = opts
        .app_name
        .clone()
        .unwrap_or_else(|| "com.tencent.qq".to_string());

    let session = with_client_version(
        SsoSession::new(
            opts.uin.clone(),
            Vec::new(),
            Vec::new(),
            [0u8; 16],
            opts.guid.clone(),
            opts.uid.clone().unwrap_or_default(),
            opts.sub_app_id,
        ),
        opts.client_version.as_deref(),
    );

    let mut conn = LoginConn::connect(opts.wrapper_path.as_deref())?;

    // 1. SsoKeyExchange
    let kx = key_exchange(&mut conn, &session, &opts.uin, &guid_bytes, deadline)?;

    // 2. SsoNTLoginEasyLogin
    let tickets = easy_login(
        &mut conn,
        &session,
        opts,
        &guid_bytes,
        &app_name,
        &opts.uin,
        &kx,
        &opts.a1,
        deadline,
    )?;

    let a2 = tickets.a2.unwrap_or_default();
    let d2 = tickets.d2.unwrap_or_default();
    let d2_key = tickets.d2_key.unwrap_or_default();
    if a2.is_empty() || d2.is_empty() || d2_key.len() != 16 {
        bail!(
            "服务端返回的票据不完整：a2={} d2={} d2key={}",
            a2.len(),
            d2.len(),
            d2_key.len()
        );
    }

    // 3. 0xcde_2 → dbkey
    let db_key = fetch_db_key(&mut conn, opts, &opts.uin, &opts.guid, &a2, &d2, &d2_key, key_meta, deadline)?;

    Ok(QuickLoginResult {
        uin: opts.uin.clone(),
        uid: opts.uid.clone(),
        guid: opts.guid.clone(),
        a2,
        d2,
        d2_key,
        db_key,
    })
}

/// 会话密钥握手结果。
struct KeyExchangeOk {
    session_key: Vec<u8>,
    session_ticket: Vec<u8>,
}

fn key_exchange(
    conn: &mut LoginConn,
    session: &SsoSession,
    uin: &str,
    guid_bytes: &[u8],
    deadline: Instant,
) -> Result<KeyExchangeOk> {
    let keypair = P256KeyPair::random()?;
    let public_key = keypair.public_key_sec1();
    let share_key = keypair.ecdh_x(&SERVER_PUBLIC_KEY)?;

    let secret_buf = KeyExchangeRequestBuf {
        uin: Some(uin.to_string()),
        guid: Some(guid_bytes.to_vec()),
    };
    let secret = crypto::aes_gcm_encrypt(&share_key, &secret_buf.encode_to_vec())?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let mut verify_packet = Vec::with_capacity(public_key.len() + 4 + secret.len() + 8);
    verify_packet.extend_from_slice(&public_key);
    verify_packet.extend_from_slice(&1u32.to_be_bytes());
    verify_packet.extend_from_slice(&secret);
    verify_packet.extend_from_slice(&0u32.to_be_bytes());
    verify_packet.extend_from_slice(&timestamp.to_be_bytes());
    let verify_hash =
        crypto::aes_gcm_encrypt(&VERIFY_HASH_KEY, &Sha256::digest(&verify_packet))?;

    let request = KeyExchangeRequest {
        public_key: public_key.clone(),
        r#type: 1,
        secret: secret.clone(),
        timestamp: timestamp as i64,
        verify_hash,
    };

    let resp = conn.transact(
        session,
        KEY_EXCHANGE_CMD,
        &request.encode_to_vec(),
        true,
        EncryptType::EncryptEmpty,
        deadline,
    )?;
    if resp.ret_code != 0 {
        bail!("SsoKeyExchange 失败：ret_code={} extra={}", resp.ret_code, resp.extra);
    }

    let kx_resp = KeyExchangeResponse::decode(resp.payload.as_slice())
        .context("解析 KeyExchangeResponse 失败")?;
    let server_pub = kx_resp
        .public_key
        .as_deref()
        .ok_or_else(|| anyhow!("KeyExchangeResponse 缺 publicKey"))?;
    let resp_share = keypair.ecdh_x(server_pub)?;
    let secret_plain = crypto::aes_gcm_decrypt(&resp_share, kx_resp.secret.as_deref().unwrap_or(&[]))
        .context("解密 KeyExchangeResponse.secret 失败")?;
    let secret_msg = KeyExchangeResponseSecret::decode(secret_plain.as_slice())
        .context("解析 KeyExchangeResponseSecret 失败")?;

    let session_key = secret_msg
        .session_key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| anyhow!("KeyExchangeResponseSecret 缺 sessionKey"))?;
    let session_ticket = secret_msg.session_ticket.unwrap_or_default();

    Ok(KeyExchangeOk {
        session_key,
        session_ticket,
    })
}

#[allow(clippy::too_many_arguments)]
fn easy_login(
    conn: &mut LoginConn,
    session: &SsoSession,
    opts: &QuickLoginOptions,
    guid_bytes: &[u8],
    app_name: &str,
    uin: &str,
    kx: &KeyExchangeOk,
    a1: &[u8],
    deadline: Instant,
) -> Result<NtLoginTickets> {
    let head = NtLoginHead {
        user_info: Some(NtLoginUserInfo {
            account: Some(uin.to_string()),
            country_code: None,
        }),
        client_info: Some(NtLoginClientInfo {
            device_type: Some(opts.os.clone()),
            device_name: Some(opts.device_name.clone()),
            platform: Some(opts.platform as u32),
            guid: Some(guid_bytes.to_vec()),
            pubno: None,
            client_ver: None,
            client_type: None,
            sso_ver: None,
        }),
        app_info: Some(NtLoginAppInfo {
            version: Some(opts.kernel_version.clone()),
            app_id: Some(opts.app_id),
            app_name: Some(app_name.to_string()),
            client_a1_version: None,
            qua: opts.qua.clone(),
        }),
        error_info: None,
        cookie: None,
        sdk_info: Some(NtLoginSdkInfo { version: Some(1) }),
    };
    let body = NtLoginEasyLoginReqBody {
        a1: Some(a1.to_vec()),
    };
    let common = NtLoginCommon {
        head: Some(head),
        body: Some(body.encode_to_vec()),
    };
    let encrypted = crypto::aes_gcm_encrypt(&kx.session_key, &common.encode_to_vec())?;
    let forward = NtLoginForwardRequest {
        session_ticket: Some(kx.session_ticket.clone()),
        buffer: Some(encrypted),
        r#type: Some(1),
        sec_buffer: None,
    };

    let resp = conn.transact(
        session,
        EASY_LOGIN_CMD,
        &forward.encode_to_vec(),
        true,
        EncryptType::EncryptEmpty,
        deadline,
    )?;
    if resp.ret_code != 0 {
        bail!("{EASY_LOGIN_CMD} 失败：ret_code={} extra={}", resp.ret_code, resp.extra);
    }

    let fwd_resp = NtLoginForwardRequest::decode(resp.payload.as_slice())
        .context("解析 NTLoginForwardRequest 失败")?;
    let buffer = fwd_resp
        .buffer
        .as_deref()
        .ok_or_else(|| anyhow!("EasyLogin 回包缺 buffer"))?;
    let plain = crypto::aes_gcm_decrypt(&kx.session_key, buffer)
        .context("解密 EasyLogin 回包失败（SessionKey 不匹配？）")?;

    let common = NtLoginCommon::decode(plain.as_slice()).context("解析回包 NTLoginCommon 失败")?;
    let err_code = common
        .head
        .as_ref()
        .and_then(|h| h.error_info.as_ref())
        .and_then(|e| e.err_code)
        .unwrap_or(0);

    if err_code == RET_UNUSUAL_DEVICE {
        bail!(
            "服务端判定为异常设备（需要手机确认/扫码）——本工具不支持该路径，已退出。\
             请确保该账号是「无需手机确认」的常规跨设备快速登录。"
        );
    }
    if err_code != 0 {
        let (title, content) = common
            .head
            .as_ref()
            .and_then(|h| h.error_info.as_ref())
            .map(|e| {
                (
                    e.str_tips_title.clone().unwrap_or_default(),
                    e.str_tips_content.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        bail!("EasyLogin 被拒绝：err_code={err_code} title={title} content={content}");
    }

    let rsp_body = common
        .body
        .as_deref()
        .ok_or_else(|| anyhow!("EasyLogin 回包缺 body"))?;
    let rsp = NtLoginEasyLoginRspBody::decode(rsp_body).context("解析 EasyLoginRspBody 失败")?;
    rsp.tickets
        .ok_or_else(|| anyhow!("EasyLogin 回包没有 Tickets"))
}

/// `OidbSvcTrpcTcp.0xcde_2`：用 a2/d2/d2key + key_meta 直接要 dbkey（同一条连接）。
#[allow(clippy::too_many_arguments)]
fn fetch_db_key(
    conn: &mut LoginConn,
    opts: &QuickLoginOptions,
    uin: &str,
    guid_hex: &str,
    a2: &[u8],
    d2: &[u8],
    d2_key: &[u8],
    key_meta: &str,
    deadline: Instant,
) -> Result<String> {
    let db_salt = validate_key_meta(key_meta)?;
    let d2_key: [u8; 16] = d2_key
        .try_into()
        .map_err(|_| anyhow!("d2key 必须 16 字节，实际 {}", d2_key.len()))?;

    let session = with_client_version(
        SsoSession::new(
            uin.to_string(),
            a2.to_vec(),
            d2.to_vec(),
            d2_key,
            guid_hex.to_string(),
            opts.uid.clone().unwrap_or_default(),
            opts.sub_app_id,
        ),
        opts.client_version.as_deref(),
    );

    let inner = crate::protocol::oidb::build_decrypt_key_body(&db_salt);
    let (cmd, envelope) = crate::protocol::oidb::build_oidb_envelope(
        crate::protocol::oidb::DECRYPT_KEY_COMMAND,
        crate::protocol::oidb::DECRYPT_KEY_SUB_COMMAND,
        inner,
        false,
    );

    let resp = conn.transact(
        &session,
        &cmd,
        &envelope,
        false,
        EncryptType::EncryptD2Key,
        deadline,
    )?;
    let body = crate::protocol::oidb::decode_oidb_reply(&resp)?;
    crate::protocol::oidb::decode_decrypt_key_reply(&body)
}

/// 校验 key_meta：必须是 128 位十六进制（大小写都收，统一返回小写）。
fn validate_key_meta(key_meta: &str) -> Result<String> {
    let lower = key_meta.to_ascii_lowercase();
    if lower.len() != 128 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "key_meta 必须是 128 位十六进制（0x2f..0xaf 的 128 字节），实际 {} 字符",
            key_meta.len()
        );
    }
    Ok(lower)
}

// ─── 传输 ─────────────────────────────────────────────────────────────────

struct LoginConn {
    stream: TcpStream,
    decoder: FrameDecoder,
    signer: Option<std::sync::Arc<Signer>>,
}

impl LoginConn {
    fn connect(wrapper_path: Option<&str>) -> Result<Self> {
        let signer = match wrapper_path {
            Some(path) if !path.is_empty() => Some(
                crate::sign::call::get_signer(std::path::Path::new(path))
                    .with_context(|| format!("加载签名器（wrapper.node）失败：{path}"))?,
            ),
            _ => bail!("未提供 wrapper.node 路径：登录命令需要签名，无法继续"),
        };
        let stream = TcpStream::connect(LOGIN_SERVER)
            .with_context(|| format!("连接登录服务器 {LOGIN_SERVER} 失败"))?;
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .context("设置读超时失败")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .context("设置写超时失败")?;
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(),
            signer,
        })
    }

    fn transact(
        &mut self,
        session: &SsoSession,
        cmd: &str,
        body: &[u8],
        need_sign: bool,
        encrypt: EncryptType,
        deadline: Instant,
    ) -> Result<SsoResponse> {
        let seq = crate::wtlogin::next_sequence();
        let sec_info = if need_sign {
            let signer = self
                .signer
                .as_ref()
                .ok_or_else(|| anyhow!("命令 {cmd} 需要签名，但没有可用的 wrapper.node 签名器"))?;
            let res = signer.sign(cmd, body, seq)?;
            Some(SsoSecureInfo {
                sec_sign: res.sign,
                sec_token: res.token,
                sec_extra: res.extra,
            })
        } else {
            None
        };
        let frame = session.build_outgoing(
            RequestType::D2Auth,
            cmd,
            seq,
            body,
            sec_info.as_ref(),
            encrypt,
        )?;
        self.stream
            .write_all(&frame)
            .with_context(|| format!("发送 {cmd} 失败"))?;
        self.stream.flush().ok();

        let ctx = session.context();
        let req_deadline = std::cmp::min(Instant::now() + REPLY_TIMEOUT, deadline);
        loop {
            if Instant::now() > req_deadline {
                bail!("等待 {cmd} 应答超时（{}s）", REPLY_TIMEOUT.as_secs());
            }
            let raw = self.read_frame(req_deadline)?;

            let sso_bytes = match packer::parse_service_layer(&ctx, &raw) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let resp = match packer::parse_sso_layer(&sso_bytes) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.sequence != seq {
                continue;
            }
            return Ok(resp);
        }
    }

    fn read_frame(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.decoder.next_frame()? {
                return Ok(frame);
            }
            let mut buf = [0u8; 16 * 1024];
            match self.stream.read(&mut buf) {
                Ok(0) => bail!("登录连接被对端关闭"),
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if Instant::now() > deadline {
                        bail!("读登录应答超时");
                    }
                    continue;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("读登录 socket 失败"),
            }
        }
    }
}

// ─── 帧解码 ───────────────────────────────────────────────────────────────

/// 从裸 TCP 字节流里按 4 字节大端总长切出完整帧。
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// 取下一整帧（含 4 字节长度前缀）。不足一帧时返回 `None`。
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len < 4 {
            bail!("非法帧长度前缀：{len}");
        }
        if self.buf.len() < len {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buf[..len].to_vec();
        self.buf.drain(..len);
        Ok(Some(frame))
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── 序号 ─────────────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicI32, Ordering};

static SEQUENCE: AtomicI32 = AtomicI32::new(0);

/// 取下一个序号（原子递增）。起点取「当前 unix 秒 + 亚秒扰动」。
pub fn next_sequence() -> i32 {
    if SEQUENCE.load(Ordering::Relaxed) == 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64;
        let jitter = (now.subsec_nanos() as i64) & 0xFFFF;
        let init = ((secs + jitter) % (i32::MAX as i64)) as i32;
        let _ = SEQUENCE.compare_exchange(0, init, Ordering::SeqCst, Ordering::Relaxed);
    }
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

// ─── Mac 端常量 ─────────────────────────────────────────────────────────

/// macOS 端的经典/NT 登录 AppInfo 常量（对齐 Lagrange `BotAppInfo`）。
pub struct OsAppInfo {
    pub wt_state: u8,
    pub wt_client_version: u16,
}

pub fn os_app_info(os: &str) -> OsAppInfo {
    match os {
        "Mac" => OsAppInfo {
            wt_state: 0x13,
            wt_client_version: 0x3374,
        },
        _ => OsAppInfo {
            wt_state: 0x13,
            wt_client_version: 0x3374,
        },
    }
}
