//! Cross-platform socket inspection for TCP and UDP.
//!
//! `netsock` provides iterators and collection APIs for enumerating sockets on
//! Linux, macOS, and Windows.

pub mod error;
pub mod family;
pub mod process;
pub mod protocol;
pub mod socket;
pub mod state;
mod sys;

/// Collects sockets that match the requested address families and protocols.
pub use sys::get_sockets;
/// Returns an iterator over sockets that match the requested filters.
pub use sys::iter_sockets;

#[cfg(any(target_os = "linux", target_os = "windows"))]
/// Returns sockets without process ownership data.
///
/// This API is intended for environments where process association is not
/// available or too expensive.
pub use sys::iter_sockets_without_processes;

#[cfg(target_os = "linux")]
/// Returns sockets using a caller-provided process cache.
pub use sys::iter_sockets_with_cache;

#[cfg(target_os = "linux")]
/// Snapshot of process-to-socket inode mappings on Linux.
pub use sys::ProcessCache;
