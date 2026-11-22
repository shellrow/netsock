mod ext;
mod proc;
mod socket_table;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;

/// Enumerates matching sockets with owner PIDs and available executable names.
pub fn iter_sockets(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    socket_table::enumerate(families, protocols, true)
}

/// Enumerates matching sockets without looking up processes.
pub fn iter_sockets_without_processes(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    socket_table::enumerate(families, protocols, false)
}
