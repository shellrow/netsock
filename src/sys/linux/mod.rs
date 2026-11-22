mod ext;
mod netlink_iter;
mod procfs;

use self::netlink_iter::NetlinkIterator;
use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use netlink_packet_sock_diag::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
pub use procfs::ProcessCache;

/// Enumerates matching sockets and attaches the owners visible through procfs.
pub fn iter_sockets(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let cache = if af_flags.intersects(AddressFamilyFlags::all())
        && proto_flags.intersects(ProtocolFlags::all())
    {
        ProcessCache::snapshot()?
    } else {
        ProcessCache::default()
    };
    iter_sockets_with_cache(af_flags, proto_flags, cache)
}

/// Returns sockets with process ownership attached using a prebuilt cache.
///
/// Reusing a cache can reduce overhead when calling this function repeatedly.
pub fn iter_sockets_with_cache(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
    cache: ProcessCache,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let sockets = iter_sockets_without_processes(af_flags, proto_flags)?;
    Ok(sockets.map(move |row| {
        row.map(|mut socket| {
            socket.processes = cache.clone_processes(socket.inode);
            socket
        })
    }))
}

/// Returns sockets without process ownership data.
pub fn iter_sockets_without_processes(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let mut iterators = Vec::with_capacity(4);
    for (flag, family) in [
        (AddressFamilyFlags::IPV4, AF_INET),
        (AddressFamilyFlags::IPV6, AF_INET6),
    ] {
        if af_flags.contains(flag) {
            for (flag, protocol) in [
                (ProtocolFlags::TCP, IPPROTO_TCP),
                (ProtocolFlags::UDP, IPPROTO_UDP),
            ] {
                if proto_flags.contains(flag) {
                    iterators.push(NetlinkIterator::new(family, protocol)?);
                }
            }
        }
    }
    Ok(iterators.into_iter().flatten())
}
