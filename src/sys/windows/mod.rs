mod ext;
mod proc;
mod socket_table;
mod socket_table_extended;
mod socket_table_iterator;

use crate::error::*;
use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use crate::sys::windows::socket_table_iterator::SocketTableIterator;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE, MIB_UDPTABLE_OWNER_PID,
};

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
    let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
    let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);
    let mut iterators = Vec::with_capacity(4);
    if ipv4 {
        if tcp {
            iterators.push(SocketTableIterator::new::<MIB_TCPTABLE_OWNER_PID>()?);
        }
        if udp {
            iterators.push(SocketTableIterator::new::<MIB_UDPTABLE_OWNER_PID>()?);
        }
    }
    if ipv6 {
        if tcp {
            iterators.push(SocketTableIterator::new::<MIB_TCP6TABLE_OWNER_PID>()?);
        }
        if udp {
            iterators.push(SocketTableIterator::new::<MIB_UDP6TABLE_OWNER_PID>()?);
        }
    }

    Ok(iterators.into_iter().flatten())
}

/// Returns sockets without process ownership data.
///
/// This function uses legacy Windows table APIs and is mainly useful for older
/// environments where owner PID data may be unavailable.
///
/// # Parameters
/// - `proto_flags`: A `ProtocolFlags` enum specifying the protocols to filter by. This can
///   include flags like `TCP` or `UDP`.
///
/// # Returns
/// A `Result` containing an iterator over `Result<SocketInfo, Error>`. Each item in the
/// iterator is a `Result` that either contains a `SocketInfo` struct with details about a
/// socket, or an `Error` indicating a problem encountered while fetching the socket information.
///
/// # Errors
/// Returns an `Error` if there is an issue creating the internal iterator, such as a failure
/// in system calls to retrieve the socket tables.
///
/// # Examples
/// ```
/// use netsock::iter_sockets_without_processes;
/// use netsock::protocol::ProtocolFlags;
///
/// let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
/// match iter_sockets_without_processes(proto_flags) {
///     Ok(sockets) => {
///         for socket in sockets {
///             match socket {
///                 Ok(info) => println!("Socket: {:?}", info),
///                 Err(e) => eprintln!("Error retrieving socket info: {:?}", e),
///             }
///         }
///     },
///     Err(e) => eprintln!("Failed to iterate over sockets: {}", e),
/// }
/// ```
///
/// This function is available only on Linux and Windows targets.
pub fn iter_sockets_without_processes(
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);

    let mut iterators = Vec::with_capacity(4);
    if tcp {
        iterators.push(SocketTableIterator::new::<MIB_TCPTABLE>()?);
    }
    if udp {
        iterators.push(SocketTableIterator::new::<MIB_UDPTABLE>()?);
    }

    Ok(iterators.into_iter().flatten())
}

#[cfg(test)]
mod tests {
    use crate::sys::windows::socket_table_iterator::SocketTableIterator;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
        MIB_UDPTABLE, MIB_UDPTABLE_OWNER_PID,
    };

    #[test]
    fn test_iterate_over_all_supported_tables() {
        let table: Vec<_> = SocketTableIterator::new::<MIB_TCPTABLE_OWNER_PID>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());

        let table: Vec<_> = SocketTableIterator::new::<MIB_UDPTABLE_OWNER_PID>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());

        let table: Vec<_> = SocketTableIterator::new::<MIB_TCP6TABLE_OWNER_PID>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());

        let table: Vec<_> = SocketTableIterator::new::<MIB_UDP6TABLE_OWNER_PID>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());

        // Old API versions.
        let table: Vec<_> = SocketTableIterator::new::<MIB_TCPTABLE>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());

        let table: Vec<_> = SocketTableIterator::new::<MIB_UDPTABLE>()
            .unwrap()
            .collect();
        assert!(!table.is_empty());
    }
}
