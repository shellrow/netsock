use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr::NonNull;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::socket::{ProtocolSocketInfo, SocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;

use super::ffi::*;
use super::proc::get_process_name;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 28;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

#[repr(C)]
struct sockaddr_in {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct sockaddr_in6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

struct ProcstatHandle(NonNull<procstat>);

impl ProcstatHandle {
    fn open() -> Result<Self, Error> {
        let handle = NonNull::new(unsafe { procstat_open_sysctl() })
            .ok_or_else(|| Error::FailedToListProcesses(std::io::Error::last_os_error()))?;
        Ok(Self(handle))
    }

    fn as_ptr(&self) -> *mut procstat {
        self.0.as_ptr()
    }
}

impl Drop for ProcstatHandle {
    fn drop(&mut self) {
        unsafe {
            procstat_close(self.as_ptr());
        }
    }
}

struct ProcList {
    procstat: *mut procstat,
    procs: NonNull<kinfo_proc>,
    count: usize,
}

impl ProcList {
    fn load(procstat: &ProcstatHandle) -> Result<Self, Error> {
        let mut count: c_uint = 0;
        let procs = NonNull::new(unsafe {
            procstat_getprocs(procstat.as_ptr(), KERN_PROC_PROC, 0, &mut count)
        })
        .ok_or_else(|| Error::FailedToListProcesses(std::io::Error::last_os_error()))?;

        Ok(Self {
            procstat: procstat.as_ptr(),
            procs,
            count: count as usize,
        })
    }

    fn get(&self, index: usize) -> Option<*mut kinfo_proc> {
        (index < self.count).then(|| unsafe { self.procs.as_ptr().add(index) })
    }
}

impl Drop for ProcList {
    fn drop(&mut self) {
        unsafe {
            procstat_freeprocs(self.procstat, self.procs.as_ptr());
        }
    }
}

struct FileList {
    procstat: *mut procstat,
    files: NonNull<filestat_list>,
}

impl FileList {
    fn load(procstat: &ProcstatHandle, process: *mut kinfo_proc) -> Option<Self> {
        let files = NonNull::new(unsafe { procstat_getfiles(procstat.as_ptr(), process, 0) })?;
        Some(Self {
            procstat: procstat.as_ptr(),
            files,
        })
    }

    fn head(&self) -> *mut filestat {
        unsafe { self.files.as_ref().stqh_first }
    }
}

impl Drop for FileList {
    fn drop(&mut self) {
        unsafe {
            procstat_freefiles(self.procstat, self.files.as_ptr());
        }
    }
}

fn parse_sockaddr(ss: &sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as i32 {
        AF_INET => {
            let sa = unsafe { &*(ss as *const sockaddr_storage).cast::<sockaddr_in>() };
            let addr = Ipv4Addr::from(sa.sin_addr);
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 => {
            let sa = unsafe { &*(ss as *const sockaddr_storage).cast::<sockaddr_in6>() };
            let addr = Ipv6Addr::from(sa.sin6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        }
        _ => None,
    }
}

fn should_include_socket(
    family: c_int,
    protocol: c_int,
    ipv4: bool,
    ipv6: bool,
    tcp: bool,
    udp: bool,
) -> bool {
    ((ipv4 && family == AF_INET) || (ipv6 && family == AF_INET6))
        && ((tcp && protocol == IPPROTO_TCP) || (udp && protocol == IPPROTO_UDP))
}

fn unspecified_addr(family: c_int) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

fn tcp_peer_details(peer: Option<SocketAddr>, family: c_int) -> (IpAddr, u16, TcpState) {
    match peer {
        Some(remote) if remote.port() != 0 || !remote.ip().is_unspecified() => {
            (remote.ip(), remote.port(), TcpState::Established)
        }
        _ => (unspecified_addr(family), 0, TcpState::Listen),
    }
}

fn fallback_process_name(process: &kinfo_proc, pid: c_int) -> String {
    let comm_ptr = process.ki_comm.as_ptr();
    if comm_ptr.is_null() {
        return format!("process_{pid}");
    }

    unsafe { CStr::from_ptr(comm_ptr) }
        .to_string_lossy()
        .into_owned()
}

fn load_socket_info(procstat: &ProcstatHandle, file: *mut filestat) -> Option<sockstat> {
    let mut sockstat = MaybeUninit::<sockstat>::uninit();
    let mut errbuf = [0 as c_char; 256];
    let status = unsafe {
        procstat_get_socket_info(
            procstat.as_ptr(),
            file,
            sockstat.as_mut_ptr(),
            errbuf.as_mut_ptr(),
        )
    };

    (status == 0).then(|| unsafe { sockstat.assume_init() })
}

pub fn iterate_netstat_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
    let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);

    let mut results = Vec::new();

    let procstat = ProcstatHandle::open()?;
    let processes = ProcList::load(&procstat)?;

    for index in 0..processes.count {
        let Some(process_ptr) = processes.get(index) else {
            continue;
        };
        let process = unsafe { &*process_ptr };
        let pid = process.ki_pid;
        if pid <= 0 {
            continue;
        }

        let Some(files) = FileList::load(&procstat, process_ptr) else {
            continue;
        };

        let mut process_name: Option<String> = None;
        let mut current_file = files.head();

        while let Some(file_ptr) = NonNull::new(current_file) {
            let file = unsafe { file_ptr.as_ref() };

            if file.fs_type == PS_FST_TYPE_SOCKET
                && let Some(sockstat) = load_socket_info(&procstat, file_ptr.as_ptr())
            {
                let family = sockstat.dom_family;
                let protocol = sockstat.proto;

                if should_include_socket(family, protocol, ipv4, ipv6, tcp, udp)
                    && let Some(local) = parse_sockaddr(&sockstat.sa_local)
                {
                    let process_name = process_name.get_or_insert_with(|| {
                        get_process_name(pid)
                            .unwrap_or_else(|_| fallback_process_name(process, pid))
                    });

                    let processes = vec![Process {
                        pid: pid as u32,
                        name: process_name.clone(),
                    }];

                    match protocol {
                        IPPROTO_TCP => {
                            let (remote_addr, remote_port, state) =
                                tcp_peer_details(parse_sockaddr(&sockstat.sa_peer), family);
                            results.push(Ok(SocketInfo {
                                protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                                    local_addr: local.ip(),
                                    local_port: local.port(),
                                    remote_addr,
                                    remote_port,
                                    state,
                                }),
                                processes,
                            }));
                        }
                        IPPROTO_UDP => {
                            results.push(Ok(SocketInfo {
                                protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                                    local_addr: local.ip(),
                                    local_port: local.port(),
                                }),
                                processes,
                            }));
                        }
                        _ => {}
                    }
                }
            }

            current_file = file.next.stqe_next;
        }
    }

    Ok(results.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};

    #[test]
    fn test_netstat() {
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();

        let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_port = udp_socket.local_addr().unwrap().port();

        let ns: Vec<_> = iterate_netstat_info(
            AddressFamilyFlags::IPV4,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        assert!(ns.iter().any(|socket| {
            matches!(
                socket.protocol_socket_info,
                ProtocolSocketInfo::Tcp(TcpSocketInfo {
                    local_addr: IpAddr::V4(addr),
                    local_port,
                    ..
                }) if addr == Ipv4Addr::LOCALHOST && local_port == tcp_port
            )
        }));

        assert!(ns.iter().any(|socket| {
            matches!(
                socket.protocol_socket_info,
                ProtocolSocketInfo::Udp(UdpSocketInfo {
                    local_addr: IpAddr::V4(addr),
                    local_port,
                }) if addr == Ipv4Addr::LOCALHOST && local_port == udp_port
            )
        }));
    }
}
