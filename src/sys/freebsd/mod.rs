mod ffi;
mod netstat;
mod proc;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::freebsd::netstat::*;

/// Returns an iterator over sockets that match the provided filters.
pub fn iter_sockets(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    iterate_netstat_info(af_flags, proto_flags)
}
