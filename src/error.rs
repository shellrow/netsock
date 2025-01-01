use std::io;
use thiserror::Error;

/// An enumeration of custom errors that might occur during system or network operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Represents a generic OS-level error.
    #[error("Failed to call ffi")]
    OsError(#[from] io::Error),

    /// Occurs when an unsupported socket family is specified.
    #[error("Unsupported SocketFamily {0}")]
    UnsupportedSocketFamily(u32),

    /// Used when listing processes fails.
    #[error("Failed to list processes")]
    FailedToListProcesses(io::Error),

    /// Occurs when an invalid socket is specified.
    #[error("Not a valid socket")]
    NotAValidSocket,

    /// Used when an invalid proc_fdtype is specified.
    #[error("{0} is not a valid proc_fdtype")]
    NotAValidFDType(u32),

    /// Used when querying file descriptors fails.
    #[error("Failed to query file descriptors")]
    FailedToQueryFileDescriptors(io::Error),

    /// Occurs when an unsupported file descriptor is encountered.
    #[error("Unsupported file descriptor")]
    UnsupportedFileDescriptor,

    /// Used when buffer allocation fails.
    #[error("Failed to allocate buffer")]
    FailedToAllocateBuffer,

    /// Occurs when retrieving the TCP table fails.
    #[error("Failed to get UDP table")]
    FailedToGetTcpTable(i32),

    /// Occurs when retrieving the UDP table fails.
    #[error("Failed to get UDP table")]
    FailedToGetUdpTable(i32),

    /// Represents a NetLink error.
    #[error("NetLink Error")]
    NetLinkError,

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("NetLink Error")]
    NetLinkPacketError(netlink_packet_core::error::ErrorMessage),

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("NetLink Decode Error")]
    NetLinkPacketDecodeError(#[from] netlink_packet_utils::errors::DecodeError),

    /// Used when an unknown protocol is found.
    #[error("Found unknown protocol {0}")]
    UnknownProtocol(u8),
}
