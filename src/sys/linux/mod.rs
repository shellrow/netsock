mod ext;
mod netlink_iter;
mod procfs;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::linux::netlink_iter::*;
use netlink_packet_sock_diag::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
pub use procfs::ProcessCache;

struct ProcessAttached<I> {
    inner: I,
    cache: ProcessCache,
}

impl<I> Iterator for ProcessAttached<I>
where
    I: Iterator<Item = Result<SocketInfo, Error>>,
{
    type Item = Result<SocketInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            result.map(|socket_info| SocketInfo {
                processes: self.cache.clone_processes(socket_info.inode),
                ..socket_info
            })
        })
    }
}

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
    let sockets = iter_sockets_without_processes(af_flags, proto_flags)?;
    let cache = ProcessCache::snapshot()?;
    Ok(attach_processes(sockets, cache))
}

pub fn iter_sockets_with_cache(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
    cache: ProcessCache,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let sockets = iter_sockets_without_processes(af_flags, proto_flags)?;
    Ok(attach_processes(sockets, cache))
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
    Ok(iterators.into_iter().flatten())
}

fn attach_processes<I>(sockets_info: I, cache: ProcessCache) -> ProcessAttached<I>
where
    I: Iterator<Item = Result<SocketInfo, Error>>,
{
    ProcessAttached {
        inner: sockets_info,
        cache,
    }
}
