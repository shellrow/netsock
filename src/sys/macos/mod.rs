mod ext;
mod ffi;
mod netstat;
mod proc;

use crate::sys::macos::netstat::*;
use crate::error::Error;
use crate::socket::SocketInfo;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;

/// Iterates over socket information based on the specified address family and protocol flags.
///
/// This function provides an iterator over `SocketInfo` structures, allowing the caller to
/// iterate through sockets filtered by address family and protocol criteria. It's a higher-level
/// abstraction over the system's netstat information.
///
/// # Parameters
/// - `af_flags`: An `AddressFamilyFlags` enum specifying the address families to filter by.
///   This can include flags like `AF_INET` for IPv4 or `AF_INET6` for IPv6.
/// - `proto_flags`: A `ProtocolFlags` enum specifying the protocols to filter by.
///   This can include flags like `TCP` or `UDP`.
///
/// # Returns
/// A `Result` containing an iterator over `Result<SocketInfo, Error>`. Each item in the iterator
/// is a `Result` that either contains a `SocketInfo` struct with details about a socket, or an
/// `Error` indicating a problem encountered while fetching the socket information.
///
/// # Errors
/// Returns an `Error` if there is a failure in fetching the netstat information, including
/// failures related to invalid parameters, system call failures, or other OS-level issues.
///
/// # Examples
/// ```
/// let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
/// let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
///
/// if let Ok(socket_iter) = iterate_sockets(af_flags, proto_flags) {
///     for socket_info in socket_iter {
///         match socket_info {
///             Ok(info) => println!("Found socket: {:?}", info),
///             Err(e) => eprintln!("Error fetching socket info: {:?}", e),
///         }
///     }
/// }
/// ```
pub fn iterate_sockets(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    iterate_netstat_info(af_flags, proto_flags)
}
