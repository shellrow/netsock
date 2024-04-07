#[macro_use]
mod ffi;

mod ext;
mod netlink_iter;
mod procfs;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::linux::netlink_iter::*;
use crate::sys::linux::procfs::*;
use libc::*;

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
    Ok(set_processes(iter_sockets_without_processes(
        af_flags,
        proto_flags,
    )?))
}

/// Iterates over socket information based on the specified address family and protocol flags.
///
/// without process info.
pub fn iter_sockets_without_processes(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
    let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);
    let mut iterators = Vec::with_capacity(4);
    unsafe {
        if ipv4 {
            if tcp {
                iterators.push(NetlinkIterator::new(AF_INET as u8, IPPROTO_TCP as u8)?);
            }
            if udp {
                iterators.push(NetlinkIterator::new(AF_INET as u8, IPPROTO_UDP as u8)?);
            }
        }
        if ipv6 {
            if tcp {
                iterators.push(NetlinkIterator::new(AF_INET6 as u8, IPPROTO_TCP as u8)?);
            }
            if udp {
                iterators.push(NetlinkIterator::new(AF_INET6 as u8, IPPROTO_UDP as u8)?);
            }
        }
    }
    Ok(iterators.into_iter().flatten())
}

fn set_processes(
    sockets_info: impl Iterator<Item = Result<SocketInfo, Error>>,
) -> impl Iterator<Item = Result<SocketInfo, Error>> {
    let mut inode_proc_map = build_inode_proc_map();
    sockets_info.map(move |r| {
        r.map(|socket_info| SocketInfo {
            processes: inode_proc_map
                .remove(&socket_info.inode)
                .unwrap_or(Vec::new()),
            ..socket_info
        })
    })
}
