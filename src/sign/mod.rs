//! 静态定位 QQ `wrapper.node` 里的签名函数（macOS：Mach-O / RTTI 锚点链）。
//!
//! 移植自 nt_helper `src/sign/`，只保留 macOS 需要的路径：
//! Itanium RTTI：name -> typeinfo -> vtable -> MSFSign -> sign core。

pub mod aarch64;
pub mod call;
pub mod decode;
pub mod elf;
pub mod image;
pub mod locate;
pub mod macho;
pub mod module_identity;
pub mod pe;
pub mod reloc;
pub mod x86;

use std::path::Path;

pub use image::{Abi, Arch, Format, Image};
pub use locate::{locate, TYPEINFO_NAME_ITANIUM};

/// 一次成功的定位结果。
#[derive(Clone, Debug)]
pub struct SignLocation {
    pub describe: String,
    pub arch: Arch,
    pub abi: Abi,
    /// 签名函数 RVA（相对模块加载基址）。
    pub rva: u64,
    pub sign_fn_addr: u64,
    pub image_base: u64,
    pub vtable_slots: usize,
    pub callback_calls: usize,
}

/// 在 `wrapper.node` 里静态定位签名函数（返回第一个命中切片）。
pub fn locate_sign(path: &Path) -> anyhow::Result<SignLocation> {
    let image = Image::open(path).map_err(anyhow::Error::msg)?;
    locate_sign_in_image(path, image.views())
}

/// 运行时目标：只认当前进程架构 + Mach-O 格式，不做跨架构回退。
pub fn locate_sign_for_target(
    path: &Path,
    arch: Arch,
    format: Format,
) -> anyhow::Result<SignLocation> {
    let image = Image::open(path).map_err(anyhow::Error::msg)?;
    let views = image
        .views_for(arch, format)
        .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    locate_sign_in_image(path, views)
}

fn locate_sign_in_image(path: &Path, views: Vec<image::View<'_>>) -> anyhow::Result<SignLocation> {
    let mut diag: Vec<String> = Vec::new();
    for view in views {
        if view.abi() == Abi::Itanium {
            match locate(&view, TYPEINFO_NAME_ITANIUM) {
                Ok(loc) => {
                    let image_base = view.image_base();
                    return Ok(SignLocation {
                        describe: view.describe(),
                        arch: view.arch(),
                        abi: Abi::Itanium,
                        rva: loc.sign_fn_addr.saturating_sub(image_base),
                        sign_fn_addr: loc.sign_fn_addr,
                        image_base,
                        vtable_slots: loc.vtable_slots,
                        callback_calls: loc.callback_calls,
                    });
                }
                Err(e) => diag.push(format!("{}: {e}", view.describe())),
            }
        }
    }
    if diag.is_empty() {
        anyhow::bail!(
            "{}: 无法解析出任何可用的架构切片（不是 Mach-O？）",
            path.display()
        )
    }
    anyhow::bail!("{}: 未定位到签名函数（{}）", path.display(), diag.join("; "))
}
