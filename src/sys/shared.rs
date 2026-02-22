use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::*;

/// Collects sockets into a `Vec` using the provided filters.
///
/// This is a convenience wrapper around [`iter_sockets`](crate::iter_sockets) for callers
/// that prefer an eagerly collected result.
///
/// # Parameters
/// - `af_flags`: Address family filters (for example, IPv4 and/or IPv6).
/// - `proto_flags`: Protocol filters (TCP and/or UDP).
///
/// # Returns
/// A `Result<Vec<SocketInfo>, Error>`.
///
/// # Errors
/// Returns an error if socket enumeration fails.
///
/// # Examples
/// ```
/// use netsock::family::AddressFamilyFlags;
/// use netsock::get_sockets;
/// use netsock::protocol::ProtocolFlags;
///
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
    iter_sockets(af_flags, proto_flags)?.collect()
}
