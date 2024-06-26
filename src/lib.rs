pub mod error;
pub mod family;
pub mod process;
pub mod protocol;
pub mod socket;
pub mod state;
mod sys;

pub use sys::get_sockets;
pub use sys::iter_sockets;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use sys::iter_sockets_without_processes;
