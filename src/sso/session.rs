//! 一场 SSO 会话的物料与组包入口。
//!
//! 为什么要单独有 `SsoSession`（而不是直接把物料丢给 `packer`）：
//!
//! * `client_conn_seq`（reserved tag 23 里的 `client_conn_seq`）在抓包里**整场会话
//!   恒定**（`/tmp/capture.log` 里 60+ 帧全是 `1791299538`），不是每包新生成的。
//!   它属于会话级状态，因此在这里生成并固定一次；`SsoContext` 只借用它。
//! * `a2/d2/d2key/guid/uin/uid/subAppId` 同样是会话级状态，集中在一处便于透传。
//!
//! `trace_parent`（tag 15）则相反：抓包里每包都不同，所以不放在会话里，仍由
//! `packer` 每包随机生成（或测试时显式指定）。

use anyhow::Result;

use super::packer::{self, EncryptType, RequestType, SsoContext};
use super::proto::SsoSecureInfo;

/// 一场会话的 SSO 物料。
#[derive(Clone, Debug)]
pub struct SsoSession {
    uin: String,
    a2: Vec<u8>,
    d2: Vec<u8>,
    d2_key: [u8; 16],
    guid: String,
    uid: String,
    sub_app_id: i32,
    /// 抓包实测为会话常量，见模块头注释。
    client_conn_seq: String,
    /// tag 15 覆盖值；`None` = 每包随机（正常行为）。
    trace_parent: Option<String>,
    /// SSO 头里的客户端版本字段（`AppInfo.CurrentVersion`，如 `3.2.31-51102`）。
    /// `None` = 写空串（旧行为）。
    client_version: Option<String>,
}

impl SsoSession {
    /// 新建会话：`client_conn_seq` 立即固定（取当前 unix 秒）。
    pub fn new(
        uin: impl Into<String>,
        a2: impl Into<Vec<u8>>,
        d2: impl Into<Vec<u8>>,
        d2_key: [u8; 16],
        guid: impl Into<String>,
        uid: impl Into<String>,
        sub_app_id: i32,
    ) -> Self {
        Self {
            uin: uin.into(),
            a2: a2.into(),
            d2: d2.into(),
            d2_key,
            guid: guid.into(),
            uid: uid.into(),
            sub_app_id,
            client_conn_seq: packer::now_unix_secs().to_string(),
            trace_parent: None,
            client_version: None,
        }
    }

    /// 覆盖 SSO 头的客户端版本字段（`AppInfo.CurrentVersion`）。
    /// 不设 = 写空串（旧行为，与抓包不一致但被服务端接受）。
    pub fn with_client_version(mut self, value: impl Into<String>) -> Self {
        self.client_version = Some(value.into());
        self
    }

    /// 固定 tag 15（`trace_parent`）。正常发包不要用——抓包里它是每包随机的。
    pub fn with_trace_parent(mut self, value: impl Into<String>) -> Self {
        self.trace_parent = Some(value.into());
        self
    }

    /// 覆盖 `client_conn_seq`（测试 / 复用既有会话时用）。
    pub fn with_client_conn_seq(mut self, value: impl Into<String>) -> Self {
        self.client_conn_seq = value.into();
        self
    }

    /// 本会话固定的 `client_conn_seq`。
    pub fn client_conn_seq(&self) -> &str {
        &self.client_conn_seq
    }

    /// 组一次请求用的借用上下文。每包调用一次，`client_conn_seq` 恒定。
    pub fn context(&self) -> SsoContext<'_> {
        SsoContext {
            uin: &self.uin,
            a2: &self.a2,
            d2: &self.d2,
            d2_key: &self.d2_key,
            guid: &self.guid,
            uid: &self.uid,
            sub_app_id: self.sub_app_id,
            // 默认每包随机（与抓包一致）；`with_trace_parent` 可钉死。
            trace_parent: self.trace_parent.clone(),
            client_conn_seq: Some(self.client_conn_seq.clone()),
            client_version: self.client_version.clone(),
        }
    }

    /// 组一个完整的线上帧（service 层 + SSO 层）。
    ///
    /// 返回的字节**已经带 4 字节大端总长度前缀**（由 service 层的长度屏障写入），
    /// 可以直接写进 TCP —— 不要再套一层长度。
    ///
    /// `sec_info` 由调用方提供：需要签名的命令先经 `sign` 模块拿到
    /// `SecSign/SecToken/SecExtra`，不需要签名时传 `None`。
    #[allow(clippy::too_many_arguments)]
    pub fn build_outgoing(
        &self,
        request_type: RequestType,
        command: &str,
        sequence: i32,
        data: &[u8],
        sec_info: Option<&SsoSecureInfo>,
        encrypt: EncryptType,
    ) -> Result<Vec<u8>> {
        packer::build_packet(
            &self.context(),
            request_type,
            command,
            sequence,
            data,
            sec_info,
            encrypt,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::packet::{Reader, PREFIX_I32};
    use crate::sso::tea;

    fn session() -> SsoSession {
        SsoSession::new(
            "1707889225",
            vec![0x11u8; 8],
            vec![0x22u8; 8],
            [0x33u8; 16],
            "917acf0aae3bc80bc1f7780942b7e050",
            "u_test",
            537_391_664,
        )
    }

    #[test]
    fn conn_seq_is_stable_within_a_session() {
        let s = session();
        let a = s.client_conn_seq().to_string();
        let b = s.context().client_conn_seq.clone().unwrap();
        let c = s.context().client_conn_seq.clone().unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert!(!a.is_empty());
    }

    #[test]
    fn conn_seq_can_be_pinned() {
        let s = session().with_client_conn_seq("1791299538");
        assert_eq!(s.client_conn_seq(), "1791299538");
        assert_eq!(s.context().client_conn_seq.as_deref(), Some("1791299538"));
    }

    #[test]
    fn outgoing_frame_decrypts_back_to_the_request() {
        let s = session();
        let frame = s
            .build_outgoing(
                RequestType::D2Auth,
                "test.cmd",
                42,
                b"payload",
                None,
                EncryptType::EncryptD2Key,
            )
            .expect("build");

        // 请求的 service 层与应答不同（请求带 d2），所以按请求字段手工解。
        let mut r = Reader::new(&frame);
        let _len = r.u32v().unwrap();
        assert_eq!(r.i32v().unwrap(), 12, "protocol");
        assert_eq!(r.u8v().unwrap(), 1, "encryptType = d2key");
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), &[0x22u8; 8], "d2");
        assert_eq!(r.u8v().unwrap(), 0, "dummy");
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), "1707889225");

        // 剩下的密文用 d2key 解开，核对 SSO 明文布局。
        let sso = tea::decrypt(r.rest(), &[0x33u8; 16]).unwrap();
        let mut o = Reader::new(&sso);
        let head = o.prefixed(PREFIX_I32).unwrap();
        assert_eq!(o.prefixed(PREFIX_I32).unwrap(), b"payload");
        let mut hr = Reader::new(head);
        assert_eq!(hr.i32v().unwrap(), 42, "sequence");
        assert_eq!(hr.i32v().unwrap(), 537_391_664, "subAppId");
        assert_eq!(hr.i32v().unwrap(), 2052);
    }

    #[test]
    fn outgoing_frame_starts_with_its_own_length() {
        let s = session();
        let frame = s
            .build_outgoing(
                RequestType::Simple,
                "Heartbeat.Alive",
                7,
                &[0, 0, 0, 4],
                None,
                EncryptType::NoEncrypt,
            )
            .expect("build");
        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len(), "总长度前缀必须等于整帧长度");
        assert_eq!(&frame[4..8], &13u32.to_be_bytes());
    }
}
