use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::*;

/// Retrieves a list of socket information filtered by address family and protocol flags.
///
/// This function collects socket information into a vector, allowing the caller to obtain a
/// comprehensive list of sockets that match the specified address family and protocol criteria.
/// It's a convenient wrapper around `iterate_sockets` for when you need to work with all sockets
/// at once, rather than iterating over them.
///
/// # Parameters
/// - `af_flags`: An `AddressFamilyFlags` enum value that specifies the address families to filter
///   the sockets by. For instance, `AF_INET` for IPv4 or `AF_INET6` for IPv6.
/// - `proto_flags`: A `ProtocolFlags` enum value that specifies the protocols to filter the
///   sockets by, such as `TCP` or `UDP`.
///
/// # Returns
/// A `Result` containing a `Vec<SocketInfo>`, where each `SocketInfo` structure provides detailed
/// information about a socket. If an error occurs during the collection of socket information,
/// the function returns an `Error`.
///
/// # Errors
/// Returns an `Error` if any issues occur while gathering the socket information. This could be due
/// to issues with the system calls, invalid parameters, or other problems encountered during
/// the operation.
///
/// # Examples
/// ```
/// let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
/// let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
///
/// match get_sockets(af_flags, proto_flags) {
///     Ok(sockets) => {
///         for socket in sockets {
///             println!("Socket: {:?}", socket);
///         }
///     },
///     Err(e) => eprintln!("Failed to get sockets: {}", e),
/// }
/// ```
pub fn get_sockets(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<Vec<SocketInfo>, Error> {
    iterate_sockets(af_flags, proto_flags)?.collect()
}
