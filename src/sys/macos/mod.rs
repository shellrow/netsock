use super::bsd::SocketRow;
use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::socket::SocketInfo;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;

const PROC_ALL_PIDS: u32 = 1;

unsafe extern "C" {
    fn netsock_fd(pid: i32, fd: i32, out: &mut SocketRow) -> i32;
}

// Both proc_listpids and PROC_PIDLISTFDS return byte counts and can fill the
// entire buffer when the list grows. Retry with room for additional entries.
fn list<T: Copy>(initial: T, mut read: impl FnMut(*mut c_void, i32) -> i32) -> io::Result<Vec<T>> {
    let mut buffer = vec![initial; 64];
    loop {
        let size = i32::try_from(size_of_val(&buffer[..])).map_err(io::Error::other)?;
        // An empty successful list returns zero without setting errno.
        unsafe { *libc::__error() = 0 };
        let used = read(buffer.as_mut_ptr().cast(), size);
        if used <= 0 {
            let err = io::Error::last_os_error();
            if used == 0 && err.raw_os_error() == Some(0) {
                return Ok(Vec::new());
            }
            return Err(err);
        }
        if used < size {
            if !(used as usize).is_multiple_of(size_of::<T>()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "partial libproc record",
                ));
            }
            buffer.truncate(used as usize / size_of::<T>());
            return Ok(buffer);
        }
        let next = buffer
            .len()
            .checked_mul(2)
            .filter(|&n| n <= i32::MAX as usize / size_of::<T>())
            .ok_or_else(|| io::Error::other("libproc list is too large"))?;
        buffer
            .try_reserve(next - buffer.len())
            .map_err(io::Error::other)?;
        buffer.resize(next, initial);
    }
}

fn unavailable(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(
            libc::ESRCH
                | libc::EBADF
                | libc::ENOENT
                | libc::EPERM
                | libc::EACCES
                | libc::ENOTSOCK
                | libc::ENOTSUP
                | libc::EINVAL
        )
    )
}

fn process_name(pid: i32) -> String {
    let mut buffer = [0u8; 1024];
    let len = unsafe { libc::proc_name(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    String::from_utf8_lossy(&buffer[..len.max(0) as usize])
        .trim_end_matches('\0')
        .to_owned()
}

fn enumerate(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    owners: bool,
) -> Result<Vec<SocketInfo>, Error> {
    let mut sockets: Vec<SocketInfo> = Vec::new();
    if !families.intersects(AddressFamilyFlags::all())
        || !protocols.intersects(ProtocolFlags::all())
    {
        return Ok(sockets);
    }
    let pids = list(0i32, |buf, bytes| unsafe {
        libc::proc_listpids(PROC_ALL_PIDS, 0, buf, bytes)
    })
    .map_err(Error::FailedToListProcesses)?;
    let mut by_id = HashMap::new();
    for pid in pids.into_iter().filter(|&pid| pid > 0) {
        let fds = match list(
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            },
            |buf, bytes| unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buf, bytes) },
        ) {
            Ok(fds) => fds,
            Err(err) if unavailable(&err) => continue,
            Err(err) => return Err(Error::FailedToQueryFileDescriptors(err)),
        };
        let mut name = None;
        for fd in fds
            .into_iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        {
            let mut row = SocketRow::default();
            match unsafe { netsock_fd(pid, fd.proc_fd, &mut row) } {
                0 => continue,
                1 => {}
                code => {
                    let err = io::Error::from_raw_os_error(-code);
                    if unavailable(&err) {
                        continue;
                    }
                    return Err(Error::FailedToQueryFileDescriptors(err));
                }
            }
            if !row.matches(families, protocols) {
                continue;
            }
            let index = if row.id == 0 {
                sockets.push(row.socket_info());
                sockets.len() - 1
            } else {
                *by_id.entry(row.id).or_insert_with(|| {
                    sockets.push(row.socket_info());
                    sockets.len() - 1
                })
            };
            let processes = &mut sockets[index].processes;
            if owners && processes.last().is_none_or(|p| p.pid != pid as u32) {
                processes.push(Process {
                    pid: pid as u32,
                    name: name.get_or_insert_with(|| process_name(pid)).clone(),
                });
            }
        }
    }
    Ok(sockets)
}

/// Enumerates sockets referenced by accessible process descriptors.
pub fn iter_sockets(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    Ok(enumerate(families, protocols, true)?.into_iter().map(Ok))
}

/// Scans accessible process descriptors without collecting owner metadata.
pub fn iter_sockets_without_processes(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    Ok(enumerate(families, protocols, false)?.into_iter().map(Ok))
}
