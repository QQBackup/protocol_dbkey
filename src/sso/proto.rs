//! SSO 保留字段与安全信息的 protobuf 定义。
//!
//! tag 以**真实抓包为准**（`/tmp/cde2.log` 的 `OidbSvcTrpcTcp.0xcde_2` proto 12
//! 明文头，以及 `Heartbeat.Alive` proto 13 未加密帧；qqshark 于 2026-10-07 抓取）。
//! 实测出现过的 tag：
//!
//! | tag | 名称            | 实测内容                                              |
//! |-----|-----------------|-------------------------------------------------------|
//! | 12  | `guid`          | 32 位小写 hex 设备 guid（Lagrange 同 tag 名为 Qimei）  |
//! | 13  | `env`           | 单字节 `00`（proto 12 有，proto 13 没有）              |
//! | 15  | `trace_parent`  | 55 字符 `00-<32hex>-<16hex>-00`（proto 12 有）         |
//! | 16  | `uid`           | `u_...`                                               |
//! | 23  | `trans_info`    | map，实测仅 `client_conn_seq=<unix 秒>`               |
//! | 24  | `sec_info`      | 签名；**两个抓包里都不存在**（见下）                   |
//! | 26  | `nt_core_version` | 实测 `101`                                          |
//!
//! 只保留本仓库会写/会读的字段；未列出的 tag 解析时直接丢弃（protobuf 兼容）。
//!
//! 关于签名：`0xcde_2` 的抓包头里 **没有 tag 24**，即没有 `SecSign/SecToken/
//! SecExtra` —— 该命令无需签名（详见 `packer.rs` 的 `capture_*` 测试）。

use prost::Message;

/// `SsoReserveFields.SsoSecureInfo`：签名函数产出的三段信息。
#[derive(Clone, PartialEq, Message)]
pub struct SsoSecureInfo {
    /// `SecSign`（tag 1）。
    #[prost(bytes = "vec", tag = "1")]
    pub sec_sign: Vec<u8>,
    /// `SecToken`（tag 2）。
    #[prost(bytes = "vec", tag = "2")]
    pub sec_token: Vec<u8>,
    /// `SecExtra`（tag 3）。
    #[prost(bytes = "vec", tag = "3")]
    pub sec_extra: Vec<u8>,
}

/// `TransInfo`（tag 23）的 map 条目；protobuf map 的线上编码就是一个
/// `repeated { key = 1; value = 2 }`。用 repeated 而非 HashMap 是为了编码顺序确定。
#[derive(Clone, PartialEq, Message)]
pub struct TransInfoEntry {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

/// SSO 头的保留字段（`SsoReserveFields`），tag 见模块头注释。
#[derive(Clone, PartialEq, Message)]
pub struct SsoReserveFields {
    /// 设备 guid（tag 12）。
    #[prost(string, optional, tag = "12")]
    pub guid: Option<String>,
    /// 环境字节（tag 13），实测 `[0x00]`。
    #[prost(bytes = "vec", optional, tag = "13")]
    pub env: Option<Vec<u8>>,
    /// 链路追踪头（tag 15），实测 `00-<32hex>-<16hex>-00`。
    #[prost(string, optional, tag = "15")]
    pub trace_parent: Option<String>,
    /// 账号 uid（tag 16）。
    #[prost(string, optional, tag = "16")]
    pub uid: Option<String>,
    /// 透传信息（tag 23）。
    #[prost(message, repeated, tag = "23")]
    pub trans_info: Vec<TransInfoEntry>,
    /// 安全信息（tag 24）—— 只有需要签名的命令才有。
    #[prost(message, optional, tag = "24")]
    pub sec_info: Option<SsoSecureInfo>,
    /// NT 内核版本（tag 26），实测 `101`。
    #[prost(uint32, optional, tag = "26")]
    pub nt_core_version: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_fields_round_trip() {
        let fields = SsoReserveFields {
            guid: Some("917acf0aae3bc80bc1f7780942b7e050".to_string()),
            env: Some(vec![0x00]),
            trace_parent: Some("00-abc-def-00".to_string()),
            uid: Some("u_abcdef".to_string()),
            trans_info: vec![TransInfoEntry {
                key: "client_conn_seq".to_string(),
                value: "1791299538".to_string(),
            }],
            sec_info: Some(SsoSecureInfo {
                sec_sign: vec![1, 2, 3],
                sec_token: vec![4, 5],
                sec_extra: Vec::new(),
            }),
            nt_core_version: Some(101),
        };
        let bytes = fields.encode_to_vec();
        let back = SsoReserveFields::decode(&bytes[..]).unwrap();
        assert_eq!(back, fields);
    }

    #[test]
    fn secure_info_uses_expected_tags() {
        let info = SsoSecureInfo {
            sec_sign: vec![0xAA],
            sec_token: vec![0xBB],
            sec_extra: vec![0xCC],
        };
        // 1 字节字段的最小编码：tag(1B) + len(1B) + 数据(1B)
        let bytes = info.encode_to_vec();
        assert_eq!(
            bytes,
            vec![0x0A, 0x01, 0xAA, 0x12, 0x01, 0xBB, 0x1A, 0x01, 0xCC]
        );
    }

    /// NT 抓包里 `guid` 是 tag 12、`uid` 是 tag 16、`trans_info` 是 tag 23。
    #[test]
    fn reserve_fields_use_capture_tags() {
        let fields = SsoReserveFields {
            guid: Some("ab".to_string()),
            uid: Some("cd".to_string()),
            ..Default::default()
        };
        // protobuf 字段长度是数据本身字节数（不含前缀）：
        // tag12 LEN = 0x62，len=2，"ab"；tag16 LEN = 0x82 0x01，len=2，"cd"
        assert_eq!(
            fields.encode_to_vec(),
            vec![0x62, 0x02, b'a', b'b', 0x82, 0x01, 0x02, b'c', b'd']
        );
    }
}
