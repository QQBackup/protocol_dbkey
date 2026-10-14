# qqdbkey

macOS 上取 NTQQ 数据库密钥（dbkey）的最小 CLI。**不需要关闭 SIP，不需要 root。**

## 用途

读取本机 QQ 已经缓存好的账号信息与设备标识，纯协议完成一次快速登录，
换回该账号 `nt_msg.db` 的 dbkey。拿到 dbkey 后就能解密本地消息数据库。

## 硬性限制（请先读）

这个工具只实现了**一条最简路径**，非核心情况一律直接报错退出，不做任何回退：

- **必须走「无需手机确认的快速登录」。** 账号需要在本机 QQ 上登录过一次
  （本地已缓存 a1），并且支持免手机确认的跨设备快登。
  如果腾讯要求扫码或手机点确认，这里**不会**退化成扫码/确认流程，会直接失败退出。
- **只支持 macOS。** 其他平台不提供适配。
- **只处理正常设备。** 账号被判定为异常设备时不会进入特殊校验流程，直接退出。
- **QQ 不需要在线。** 只要本地 `login.db` 里已经有该账号数据即可。
- 任何一步缺失（没有 a1、没有 login.db、没有 nt_msg.db、没有 key_meta 等）都会
  明确报错并退出，不会尝试绕过。

## 环境要求

- macOS，本机装过 QQ 并且目标账号登录过
- 需要能读到 QQ 的安装目录与数据目录（默认路径自动探测）
- 重新编译需要 Rust（edition 2024，`rust-version = 1.85`）

## 编译

```sh
cargo build --release
```

## 使用

```sh
# 自动探测路径，交互式选择账号
./target/release/qqdbkey

# 非交互，直接指定账号
./target/release/qqdbkey --uin <UIN>

# 手动指定路径
./target/release/qqdbkey --data-root <QQ数据根> --install-root <QQ.app/Contents/Resources/app>
```

- `--data-root`：QQ 数据根，默认 macOS 沙盒容器路径。
- `--install-root`：QQ 的 `Resources/app` 目录（含 `wrapper.node` / `major.node`）。
- `--uin`：非交互模式，跳过选择界面。

交互模式下会用 ↑/↓ 或鼠标从 `login.db` 列出的账号里选择。

## 输出

成功时打印握手得到的会话信息，最后一行是目标：

```
dbkey   <你需要的数据库密钥>
```

把 dbkey 用于解密对应账号的 `nt_msg.db` 即可（解密/导出不在本工具范围内）。
