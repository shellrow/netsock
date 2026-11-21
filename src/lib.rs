#![doc = include_str!("../README.md")]

pub mod error;
pub mod family;
pub mod process;
pub mod protocol;
pub mod socket;
pub mod state;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_os = "freebsd"
)))]
compile_error!("netsock supports Linux, macOS, Windows, and FreeBSD");

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_os = "freebsd"
))]
mod sys;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_os = "freebsd"
))]
pub use sys::{iter_sockets, iter_sockets_without_processes};

#[cfg(target_os = "linux")]
pub use sys::{ProcessCache, iter_sockets_with_cache};

/// Collects matching sockets, returning the first enumeration error.
///
/// Ownership is best effort. Permissions and concurrent process exits may
/// leave the owner list empty. On macOS only accessible descriptors are visible.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    windows,
    target_os = "freebsd"
))]
pub fn get_sockets(
    families: family::AddressFamilyFlags,
    protocols: protocol::ProtocolFlags,
) -> Result<Vec<socket::SocketInfo>, error::Error> {
    iter_sockets(families, protocols)?.collect()
}
