mod ext;
mod netstat;
mod proc;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::macos::netstat::*;

/// Returns an iterator over sockets that match the provided filters.
///
/// # Examples
/// ```
/// use netsock::family::AddressFamilyFlags;
/// use netsock::iter_sockets;
/// use netsock::protocol::ProtocolFlags;
///
/// let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
/// let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
///
/// if let Ok(socket_iter) = iter_sockets(af_flags, proto_flags) {
///     for socket_info in socket_iter {
///         match socket_info {
///             Ok(info) => println!("Found socket: {:?}", info),
///             Err(e) => eprintln!("Error fetching socket info: {:?}", e),
///         }
///     }
/// }
/// ```
pub fn iter_sockets(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    iterate_netstat_info(af_flags, proto_flags)
}
