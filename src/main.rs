//! qqdbkey — macOS 上**无需 SIP / 无需 root**，凭本地 `login.db` 的 a1 + 设备 guid
//! 走纯协议快速登录，取回 NTQQ 数据库密钥（dbkey）。
//!
//! 流程：
//! 1. 定位 QQ 数据根 + 安装根；
//! 2. 从 `major.node` 扫 appid / qua / version；
//! 3. 手写解密 `login.db`（含 -wal 合并），列出账号；
//! 4. 选账号 → 算 guid、读 `nt_msg.db` 的 key_meta、解 a1；
//! 5. 定位 `wrapper.node` 签名函数 → SsoKeyExchange → EasyLogin → 0xcde_2 → dbkey。
//!
//! 只走快登：没有 a1 / 异常设备 / 任何报错都直接退出，不做二维码或确认回退。

// 移植自 nt_helper / WeQ 的逻辑保留了完整的容器解析、协议与加密路径，
// 当前 CLI 只走其中一条；未用到的项并非死码，不做删除。
#![allow(dead_code)]

mod login_db;
mod macos;
mod protocol;
mod sign;
mod sso;
mod ui;
mod wtlogin;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "qqdbkey",
    version,
    about = "macOS 无 SIP / 无 root，凭本地 login.db 纯协议换取 NTQQ dbkey",
    long_about = "从本机 login.db 解出 a1 与设备 guid，纯协议完成快速登录并换回 NTQQ 数据库密钥（dbkey）。\n\
不需要 QQ 在线，不需要 SIP 关闭，也不需要 root。"
)]
struct Cli {
    /// 手动指定 QQ 数据根（默认 macOS 沙盒容器路径）。
    #[arg(long)]
    data_root: Option<PathBuf>,

    /// 手动指定 QQ.app 的 Resources/app 目录（含 wrapper.node / major.node）。
    #[arg(long)]
    install_root: Option<PathBuf>,

    /// 非交互：直接对指定 uin 执行，不弹出选择界面。
    #[arg(long)]
    uin: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ui::error(&format!("{e:#}"));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    ui::app_banner("macOS · 纯协议获取 NTQQ dbkey（无 SIP / 无 root）");

    let home = dirs_home()?;

    // ── 1. 数据根 ────────────────────────────────────────────────
    let root = match &cli.data_root {
        Some(p) if p.exists() => p.clone(),
        Some(p) => bail!("指定的 --data-root 不存在：{}", p.display()),
        None => macos::pick_root(&home, None)
            .ok_or_else(|| anyhow::anyhow!("未找到 QQ 数据根（请确认 QQ 已登录过）"))?,
    };
    ui::section("环境");
    ui::field("数据根", &root.display().to_string());

    // ── 2. major.node → appid / qua / version ────────────────────
    let info = macos::resolve_appid_info_opt(&home, cli.install_root.as_deref())?;
    ui::field("subAppId", &info.appid);
    if let Some(q) = &info.qua {
        ui::field("QUA", q);
    }
    let client_version = match (&info.version, &info.build) {
        (Some(v), Some(b)) => Some(format!("{v}-{b}")),
        _ => None,
    };

    // ── 3. login.db → 账号列表 ───────────────────────────────────
    ui::section("账号");
    let dbs = macos::login_dbs(&home, Some(&root));
    if dbs.is_empty() {
        bail!("未找到 login.db（QQ 从未在此机器登录过？）");
    }
    for p in &dbs {
        ui::field("login.db", &p.display().to_string());
    }
    let (accounts, _algo) = login_db::read_accounts_merged(&dbs)
        .with_context(|| format!("解密 login.db 失败：{}", dbs[0].display()))?;
    if accounts.is_empty() {
        bail!("login.db 解密成功，但未列出任何账号");
    }

    // ── 4. 选择账号 ──────────────────────────────────────────────
    let chosen = match &cli.uin {
        Some(u) => accounts
            .iter()
            .find(|a| &a.uin == u)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("login.db 里没有 uin={u}"))?,
        None => {
            let choices: Vec<ui::Choice> = accounts
                .iter()
                .map(|a| ui::Choice {
                    uin: a.uin.clone(),
                    nick: a.nick.clone(),
                    uid: a.uid.clone(),
                    last_login_at: a.last_login_at,
                })
                .collect();
            let idx = ui::select_account(&choices)?;
            accounts[idx].clone()
        }
    };
    ui::ok(&format!("已选择账号 {} ({})", chosen.uin, if chosen.nick.is_empty() { "-" } else { &chosen.nick }));
    ui::field("uid", &chosen.uid);

    // ── 5. guid / a1 / key_meta ──────────────────────────────────
    let guid = macos::device_guid(&root)
        .ok_or_else(|| anyhow::anyhow!("无法计算本机设备 guid（machineid-info 缺失且硬件回退失败）"))?;
    ui::field("guid", &guid);

    let guid_bytes = hex::decode(&guid).context("guid 解码失败")?;
    let a1 = macos::decrypt_a1_payload(&chosen.a1_blob, &guid_bytes)
        .ok_or_else(|| anyhow::anyhow!("该账号没有可用的 a1（请先在 QQ 客户端登录一次以缓存 a1）"))?;
    ui::field("a1 长度", &format!("{} 字节", a1.len()));

    let db_path = macos::nt_msg_db(&home, Some(&root), &chosen.uid)
        .ok_or_else(|| anyhow::anyhow!("未找到该账号的 nt_msg.db（无法读 key_meta）"))?;
    let key_meta = macos::read_key_meta(&db_path)
        .ok_or_else(|| anyhow::anyhow!("{} 的 key_meta 读取失败/格式非法", db_path.display()))?;
    ui::field("nt_msg.db", &db_path.display().to_string());
    ui::field("key_meta", &format!("{}…", &key_meta[..16]));

    // ── 6. wrapper.node 签名器 ───────────────────────────────────
    let wrapper = macos::wrapper_node_for(&home, cli.install_root.as_deref())?;
    ui::section("登录");
    ui::field("wrapper.node", &wrapper.display().to_string());
    let signer = sign::call::get_signer(&wrapper)
        .with_context(|| format!("加载签名器失败：{}", wrapper.display()))?;
    ui::ok(&format!("定位签名函数：{} rva=0x{:x}", signer.describe, signer.rva));

    // ── 7. 快速登录 + 0xcde_2 → dbkey ────────────────────────────
    let opts = wtlogin::QuickLoginOptions {
        uin: chosen.uin.clone(),
        a1,
        guid: guid.clone(),
        app_id: 1600001602, // Mac 端 EasyLogin AppId（非 subAppId）
        sub_app_id: info.appid.parse().context("major.node 的 appid 不是数字")?,
        os: "Mac".to_string(),
        platform: 5, // NTLoginPlatform: Mac=5
        device_name: hostname(),
        kernel_version: kernel_version(),
        app_name: None,
        qua: info.qua.clone(),
        client_version,
        wrapper_path: Some(wrapper.display().to_string()),
        uid: Some(chosen.uid.clone()),
        key_meta: Some(key_meta),
    };

    ui::info("正在与登录服务器协商会话密钥 / 换取 a2·d2 / 请求 dbkey…");
    let result = wtlogin::quick_login_blocking(&opts)?;

    // ── 8. 结果 ──────────────────────────────────────────────────
    ui::section("结果");
    ui::field("uin", &result.uin);
    if let Some(uid) = &result.uid {
        ui::field("uid", uid);
    }
    ui::field("guid", &result.guid);
    ui::field("a2", &format!("{} 字节", result.a2.len()));
    ui::field("d2", &format!("{} 字节", result.d2.len()));
    ui::field("d2key", &format!("{} 字节", result.d2_key.len()));
    println!();
    ui::key_line("dbkey", &result.db_key);
    println!();
    ui::ok("完成。");
    Ok(())
}

fn dirs_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("环境变量 HOME 未设置"))
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Mac".to_string())
}

fn kernel_version() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
