#[cfg(any(
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod bsd;
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
#[cfg_attr(any(target_os = "freebsd", target_os = "netbsd"), path = "bsd_pcbs.rs")]
#[cfg_attr(target_os = "openbsd", path = "openbsd/mod.rs")]
mod platform;

pub use platform::*;
