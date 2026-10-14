//! 跨平台加载 `wrapper.node` 并调用定位到的签名函数（macOS：dlopen + dyld）。
//!
//! 流程：
//! 1. [`super::locate_sign`] 静态扫描 `wrapper.node`，得到签名函数 RVA；
//! 2. dlopen 该文件；取模块加载基址，`签名函数 = 基址 + RVA`；
//! 3. 调用 `sign(cmd, src, len, seq, out)`，切出 token/extra/sign。
//!
//! `wrapper.node` 引用宿主（Electron/QQ 的 JS 层）提供的 `qq_magic_napi_register`。
//! 这里从本进程自身导出同名空桩，并把自身提升为 `RTLD_GLOBAL`，让随后 dlopen 的
//! `wrapper.node` 通过 dyld dynamic lookup 解析到它。

use std::collections::HashMap;
use std::ffi::c_char;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use libloading::os::unix::Library as DynLib;

use super::{Arch, Format, locate_sign_for_target};

/// `int sign(const char *cmd, const uint8_t *src, size_t src_len, int seq, uint8_t *out)`
type SignFn = unsafe extern "C" fn(*const c_char, *const u8, usize, i32, *mut u8) -> i32;

const TOKEN_LEN_OFFSET: usize = 0xFF;
const EXTRA_DATA_OFFSET: usize = 0x100;
const EXTRA_LEN_OFFSET: usize = 0x1FF;
const SIGN_DATA_OFFSET: usize = 0x200;
const SIGN_LEN_OFFSET: usize = 0x2FF;
const OUT_BUF_LEN: usize = 0x400;

/// 一次签名计算的结果（十六进制未编码的原始字节）。
#[derive(Clone, Debug, Default)]
pub struct SignResult {
    pub token: Vec<u8>,
    pub extra: Vec<u8>,
    pub sign: Vec<u8>,
}

/// 宿主（QQ JS 层）应提供的桩符号。空实现，只为满足动态符号解析。
#[unsafe(no_mangle)]
pub extern "C" fn qq_magic_napi_register(_ptr: *mut std::ffi::c_void) {}

fn runtime_target() -> Result<(Arch, Format)> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::AArch64,
        other => return Err(anyhow!("不支持的进程架构: {other}")),
    };
    if std::env::consts::OS != "macos" {
        return Err(anyhow!("本工具只适配 macOS"));
    }
    Ok((arch, Format::MachO))
}

/// 把已加载进进程的自身模块提升为 `RTLD_GLOBAL`，使导出的
/// `qq_magic_napi_register` 桩对随后 dlopen 的 `wrapper.node` 可见。
#[cfg(target_os = "macos")]
fn promote_self_global() {
    use std::ffi::CStr;
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        let sym = qq_magic_napi_register as *const std::ffi::c_void;
        if libc::dladdr(sym, &mut info) == 0 || info.dli_fname.is_null() {
            return;
        }
        let path = CStr::from_ptr(info.dli_fname);
        // 句柄有意泄漏：模块本就常驻，提升只是修改属性。
        let _ = libc::dlopen(
            path.as_ptr(),
            libc::RTLD_NOW | libc::RTLD_GLOBAL | libc::RTLD_NOLOAD,
        );
    }
}

/// macOS：用 dyld 的镜像列表按完整路径匹配，取该镜像的 vmaddr slide 作为基址。
/// Mach-O 切片 vmaddr 从 0 起算，因此 `基址 = slide`。
#[cfg(target_os = "macos")]
fn module_base(wrapper: &Path) -> Result<u64> {
    use std::ffi::CStr;

    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(index: u32) -> *const c_char;
        fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
    }

    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name = CStr::from_ptr(name_ptr).to_string_lossy();
            if super::module_identity::same_module_path(Path::new(name.as_ref()), wrapper) {
                return Ok(_dyld_get_image_vmaddr_slide(i) as u64);
            }
        }
    }
    Err(anyhow!("dyld 镜像列表里没有目标模块 {}", wrapper.display()))
}

#[cfg(not(target_os = "macos"))]
fn promote_self_global() {}

#[cfg(not(target_os = "macos"))]
fn module_base(_wrapper: &Path) -> Result<u64> {
    Err(anyhow!("本工具只适配 macOS，无法加载 wrapper.node"))
}

/// dlopen 失败时给出可操作的诊断。
///
/// 未签名的二进制加载「官方签名完好」的 `wrapper.node` 是允许的，所以这里通常
/// 不是缺 entitlement。最常见的真实原因是 QQ.app 被改动过（例如装过注入插件、
/// 动过 `Resources/app`），导致整个 bundle 的代码签名失效，bundle 内的
/// framework / dylib 都会被系统策略拒绝。这种情况重装官方 QQ 即可，工具不做绕过。
#[cfg(target_os = "macos")]
fn dlopen_hint(wrapper: &Path) -> String {
    let Some(app) = wrapper.ancestors().find(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(".app"))
    }) else {
        return String::new();
    };
    let status = std::process::Command::new("codesign")
        .args(["--verify", "--verbose=1"])
        .arg(app)
        .output();
    let Ok(status) = status else {
        return String::new();
    };
    if status.status.success() {
        return String::new();
    }
    let detail = String::from_utf8_lossy(&status.stderr);
    let detail: Vec<&str> = detail.lines().filter(|l| !l.trim().is_empty()).collect();
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!("\n  codesign 报错：{}", detail.join("；"))
    };
    format!(
        "hint: {} 的代码签名已失效（多半是被改动过），系统会拒绝加载它内部的库。\n  \
         请重装官方 QQ 后重试；本工具不会绕过签名校验。{detail}",
        app.display()
    )
}

#[cfg(not(target_os = "macos"))]
fn dlopen_hint(_wrapper: &Path) -> String {
    String::new()
}

/// 已加载并定位到签名函数的 `wrapper.node` 签名器。
pub struct Signer {
    _lib: DynLib,
    sign: SignFn,
    pub rva: u64,
    pub describe: String,
}

impl Signer {
    pub fn load(wrapper: &Path) -> Result<Self> {
        let (arch, format) = runtime_target()?;
        let loc = locate_sign_for_target(wrapper, arch, format)?;
        promote_self_global();
        // SAFETY: dlopen 一个刻意加载的本地原生模块。
        let lib = unsafe { DynLib::new(wrapper) }.map_err(|e| {
            anyhow!(
                "加载 {} 失败（dlopen）：{e}\n{}",
                wrapper.display(),
                dlopen_hint(wrapper)
            )
        })?;
        let base = module_base(wrapper)
            .with_context(|| format!("找不到已加载模块的基址：{}", wrapper.display()))?;
        let addr = base
            .checked_add(loc.rva)
            .ok_or_else(|| anyhow!("签名函数地址溢出：base=0x{base:x} rva=0x{:x}", loc.rva))?;
        let sign: SignFn = unsafe { std::mem::transmute(addr as *const ()) };
        Ok(Self {
            _lib: lib,
            sign,
            rva: loc.rva,
            describe: loc.describe,
        })
    }

    /// 计算一次签名。`src` 是 SSO 包体（明文 protobuf 字节）。
    pub fn sign(&self, cmd: &str, src: &[u8], seq: i32) -> Result<SignResult> {
        let c_cmd =
            std::ffi::CString::new(cmd).map_err(|_| anyhow!("命令字符串含 NUL 字节：{cmd:?}"))?;
        let mut out = [0u8; OUT_BUF_LEN];
        let ret = unsafe {
            (self.sign)(
                c_cmd.as_ptr(),
                src.as_ptr(),
                src.len(),
                seq,
                out.as_mut_ptr(),
            )
        };
        if ret != 0 {
            // 签名函数本身通常返回 0；非 0 只记日志，不致命。
        }
        let token = slice_out(&out, 0, out[TOKEN_LEN_OFFSET], "token")?;
        let extra = slice_out(&out, EXTRA_DATA_OFFSET, out[EXTRA_LEN_OFFSET], "extra")?;
        let sign = slice_out(&out, SIGN_DATA_OFFSET, out[SIGN_LEN_OFFSET], "sign")?;
        Ok(SignResult { token, extra, sign })
    }
}

fn slice_out(out: &[u8; OUT_BUF_LEN], start: usize, len: u8, field: &str) -> Result<Vec<u8>> {
    let end = start + len as usize;
    if end > out.len() {
        return Err(anyhow!(
            "签名输出越界：{field} start=0x{start:x} len={len} 超过缓冲区 {OUT_BUF_LEN}"
        ));
    }
    Ok(out[start..end].to_vec())
}

// ─── 签名器缓存 ──────────────────────────────────────────────────────

static SIGNERS: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<Signer>>>> =
    std::sync::OnceLock::new();

/// 取（必要时加载）某个 `wrapper.node` 的签名器；同路径只加载一次。
pub fn get_signer(wrapper: &Path) -> Result<Arc<Signer>> {
    let map = SIGNERS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let key = wrapper.to_path_buf();
    {
        let guard = map.lock().unwrap();
        if let Some(existing) = guard.get(&key) {
            return Ok(Arc::clone(existing));
        }
    }
    let signer = Arc::new(Signer::load(wrapper)?);
    map.lock().unwrap().insert(key, Arc::clone(&signer));
    Ok(signer)
}
