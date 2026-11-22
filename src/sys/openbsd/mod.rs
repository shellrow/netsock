use super::bsd::SocketRow;
use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_void};
use std::io;

unsafe extern "C" {
    fn netsock_files(
        owners: i32,
        ctx: *mut c_void,
        visit: extern "C" fn(*mut c_void, &SocketRow, u32, u32, *const c_char),
    ) -> i32;
}

#[derive(Eq, Hash, PartialEq)]
enum SocketKey {
    Pcb(u64),
    Endpoints {
        rtable: u32,
        ipv6: u8,
        tcp: u8,
        local: [u8; 16],
        remote: [u8; 16],
        local_port: u16,
        remote_port: u16,
    },
}

impl SocketKey {
    fn new(row: &SocketRow, rtable: u32) -> Self {
        if row.id != 0 {
            return Self::Pcb(row.id);
        }
        Self::Endpoints {
            rtable,
            ipv6: row.ipv6,
            tcp: row.tcp,
            local: row.local,
            remote: row.remote,
            local_port: row.local_port,
            remote_port: row.remote_port,
        }
    }
}

struct Snapshot {
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    owners: bool,
    sockets: Vec<SocketInfo>,
    indices: HashMap<SocketKey, Option<usize>>,
}

// KERN_FILE_BYFILE supplies one row per socket, including sockets without an
// open descriptor. KERN_FILE_BYPID then supplies each visible descriptor.
extern "C" fn record(
    ctx: *mut c_void,
    row: &SocketRow,
    rtable: u32,
    pid: u32,
    name: *const c_char,
) {
    let scan = unsafe { &mut *ctx.cast::<Snapshot>() };
    if !row.matches(scan.families, scan.protocols) {
        return;
    }
    if pid == 0 {
        if scan.owners {
            // Identical endpoints can belong to distinct SO_REUSEPORT sockets.
            scan.indices
                .entry(SocketKey::new(row, rtable))
                .and_modify(|index| *index = None)
                .or_insert(Some(scan.sockets.len()));
        }
        scan.sockets.push(row.socket_info());
    } else if let Some(&Some(i)) = scan.indices.get(&SocketKey::new(row, rtable)) {
        let socket = &mut scan.sockets[i];
        if !socket.is_owned_by_pid(pid) {
            let name = unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned();
            socket.processes.push(Process { pid, name });
        }
    }
}

fn enumerate(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    owners: bool,
) -> Result<Vec<SocketInfo>, Error> {
    if !families.intersects(AddressFamilyFlags::all())
        || !protocols.intersects(ProtocolFlags::all())
    {
        return Ok(Vec::new());
    }
    let mut scan = Snapshot {
        families,
        protocols,
        owners,
        sockets: Vec::new(),
        indices: HashMap::new(),
    };
    let ctx = (&raw mut scan).cast();
    let status = unsafe { netsock_files(0, ctx, record) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status).into());
    }
    if !scan.indices.is_empty() {
        let status = unsafe { netsock_files(1, ctx, record) };
        if status != 0 {
            let err = io::Error::from_raw_os_error(status);
            if err.kind() != io::ErrorKind::PermissionDenied {
                return Err(Error::FailedToQueryFileDescriptors(err));
            }
        }
    }
    Ok(scan.sockets)
}

/// Enumerates kernel socket records and attaches visible file descriptor owners.
pub fn iter_sockets(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    Ok(enumerate(families, protocols, true)?.into_iter().map(Ok))
}

/// Enumerates kernel socket records without querying file descriptor owners.
pub fn iter_sockets_without_processes(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    Ok(enumerate(families, protocols, false)?.into_iter().map(Ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_socket_ids_require_unique_endpoints_within_the_routing_table() {
        let mut scan = Snapshot {
            families: AddressFamilyFlags::IPV4,
            protocols: ProtocolFlags::UDP,
            owners: true,
            sockets: Vec::new(),
            indices: HashMap::new(),
        };
        let ctx = (&raw mut scan).cast();
        let row = SocketRow::default();
        let name = c"test".as_ptr();

        record(ctx, &row, 0, 0, name);
        record(ctx, &row, 0, 0, name);
        record(ctx, &row, 1, 0, name);
        record(ctx, &row, 0, 42, name);
        record(ctx, &row, 1, 43, name);

        assert_eq!(scan.sockets.len(), 3);
        assert!(scan.sockets[0].processes.is_empty());
        assert!(scan.sockets[1].processes.is_empty());
        assert!(scan.sockets[2].is_owned_by_pid(43));
    }
}
