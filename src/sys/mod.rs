#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod bsd;
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
#[cfg_attr(target_os = "freebsd", path = "freebsd/mod.rs")]
mod platform;

pub use platform::*;
