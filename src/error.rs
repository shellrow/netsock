use std::io;
use thiserror::Error;

/// An enumeration of custom errors that might occur during system or network operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Represents a generic OS-level error.
    #[error("OS error while calling FFI")]
    OsError(#[from] io::Error),

    /// Occurs when an unsupported socket family is specified.
    #[error("unsupported socket family: {0}")]
    UnsupportedSocketFamily(u32),

    /// Used when listing processes fails.
    #[error("failed to list processes")]
    FailedToListProcesses(#[source] io::Error),

    /// Occurs when an invalid socket is specified.
    #[error("not a valid socket")]
    NotAValidSocket,

    /// Used when an invalid proc_fdtype is specified.
    #[error("not a valid proc_fdtype: {0}")]
    NotAValidFDType(u32),

    /// Used when querying file descriptors fails.
    #[error("failed to query file descriptors")]
    FailedToQueryFileDescriptors(#[source] io::Error),

    /// Occurs when an unsupported file descriptor is encountered.
    #[error("unsupported file descriptor")]
    UnsupportedFileDescriptor,

    /// Used when buffer allocation fails.
    #[error("failed to allocate buffer")]
    FailedToAllocateBuffer,

    /// Occurs when retrieving the TCP table fails.
    #[error("failed to get TCP table: {0}")]
    FailedToGetTcpTable(i32),

    /// Occurs when retrieving the UDP table fails.
    #[error("failed to get UDP table: {0}")]
    FailedToGetUdpTable(i32),

    /// Represents a NetLink error.
    #[error("netlink error")]
    NetLinkError,

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("netlink error: {0}")]
    NetLinkPacketError(netlink_packet_core::error::ErrorMessage),

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("netlink decode error")]
    NetLinkPacketDecodeError(#[from] netlink_packet_utils::errors::DecodeError),

    /// Used when an unknown protocol is found.
    #[error("unknown protocol: {0}")]
    UnknownProtocol(u8),
}
