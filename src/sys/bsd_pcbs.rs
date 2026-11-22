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
    fn netsock_pcbs(
        tcp: i32,
        ipv4: i32,
        ipv6: i32,
        ctx: *mut c_void,
        visit: extern "C" fn(*mut c_void, &SocketRow),
    ) -> i32;
    fn netsock_owners(ctx: *mut c_void, visit: extern "C" fn(*mut c_void, u64, u32)) -> i32;
    fn netsock_process_name(pid: i32, buf: *mut c_char, size: usize);
}

struct Snapshot {
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    sockets: Vec<SocketInfo>,
    indices: HashMap<u64, usize>,
    names: HashMap<u32, String>,
    owners: bool,
}

// The C callbacks run synchronously with the unique Snapshot pointer supplied
// by enumerate. Socket identities are never exposed outside this snapshot.
extern "C" fn add_socket(ctx: *mut c_void, row: &SocketRow) {
    let scan = unsafe { &mut *ctx.cast::<Snapshot>() };
    if row.matches(scan.families, scan.protocols) {
        if scan.owners && row.id != 0 {
            scan.indices.insert(row.id, scan.sockets.len());
        }
        scan.sockets.push(row.socket_info());
    }
}

extern "C" fn add_owner(ctx: *mut c_void, id: u64, pid: u32) {
    let scan = unsafe { &mut *ctx.cast::<Snapshot>() };
    if let Some(&i) = scan.indices.get(&id) {
        let socket = &mut scan.sockets[i];
        if !socket.is_owned_by_pid(pid) {
            let name = scan.names.entry(pid).or_insert_with(|| {
                let mut buf = [0; 256];
                unsafe {
                    netsock_process_name(pid as i32, buf.as_mut_ptr(), buf.len());
                    CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
                }
            });
            socket.processes.push(Process {
                pid,
                name: name.clone(),
            });
        }
    }
}

fn enumerate(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    owners: bool,
) -> Result<Vec<SocketInfo>, Error> {
    let mut scan = Snapshot {
        families,
        protocols,
        sockets: Vec::new(),
        indices: HashMap::new(),
        names: HashMap::new(),
        owners,
    };
    let ctx = (&raw mut scan).cast();
    if families.intersects(AddressFamilyFlags::all()) {
        for proto in [ProtocolFlags::TCP, ProtocolFlags::UDP] {
            if protocols.contains(proto) {
                let status = unsafe {
                    netsock_pcbs(
                        i32::from(proto == ProtocolFlags::TCP),
                        i32::from(families.contains(AddressFamilyFlags::IPV4)),
                        i32::from(families.contains(AddressFamilyFlags::IPV6)),
                        ctx,
                        add_socket,
                    )
                };
                if status != 0 {
                    return Err(io::Error::from_raw_os_error(status).into());
                }
            }
        }
    }
    if !scan.indices.is_empty() {
        let status = unsafe { netsock_owners(ctx, add_owner) };
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
