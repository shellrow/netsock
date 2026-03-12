use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::c_uint;

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

fn parse_sockaddr(ss: &sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as i32 {
        AF_INET => {
            let sa = unsafe { &*(ss as *const sockaddr_storage as *const sockaddr_in) };
            let addr = Ipv4Addr::from(sa.sin_addr);
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 => {
            let sa = unsafe { &*(ss as *const sockaddr_storage as *const sockaddr_in6) };
            let addr = Ipv6Addr::from(sa.sin6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        }
        _ => None,
    }
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

    unsafe {
        let ps = procstat_open_sysctl();
        if ps.is_null() {
            return Err(Error::FailedToListProcesses(std::io::Error::last_os_error()));
        }

        let mut count: c_uint = 0;
        let procs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &mut count);
        if procs.is_null() {
            procstat_close(ps);
            return Err(Error::FailedToListProcesses(std::io::Error::last_os_error()));
        }

        for i in 0..count as isize {
            let kp = procs.offset(i);
            if kp.is_null() {
                continue;
            }
            
            let pid = (*kp).ki_pid;
            if pid <= 0 {
                continue;
            }

            let files = procstat_getfiles(ps, kp, 0);
            if files.is_null() {
                continue;
            }

            let mut process_name: Option<String> = None;
            let mut current_file = (*files).stqh_first;

            while !current_file.is_null() {
                let fst = &*current_file;
                
                if fst.fs_type == PS_FST_TYPE_SOCKET {
                    let mut sockstat: sockstat = mem::zeroed();
                    let mut errbuf = [0i8; 256];
                    
                    let ret = procstat_get_socket_info(
                        ps,
                        current_file,
                        &mut sockstat,
                        errbuf.as_mut_ptr(),
                    );

                    if ret == 0 {
                        let family = sockstat.dom_family;
                        let proto = sockstat.proto;
                        
                        let should_include = 
                            ((ipv4 && family == AF_INET) || (ipv6 && family == AF_INET6)) &&
                            ((tcp && proto == IPPROTO_TCP) || (udp && proto == IPPROTO_UDP));

                        if should_include {
                            if let Some(local) = parse_sockaddr(&sockstat.sa_local) {
                                let pname = process_name.get_or_insert_with(|| {
                                    get_process_name(pid).unwrap_or_else(|_| {
                                        let comm_ptr = (*kp).ki_comm.as_ptr();
                                        if !comm_ptr.is_null() {
                                            CStr::from_ptr(comm_ptr)
                                                .to_string_lossy()
                                                .to_string()
                                        } else {
                                            format!("process_{}", pid)
                                        }
                                    })
                                });

                                let processes = vec![Process {
                                    pid: pid as u32,
                                    name: pname.clone(),
                                }];

                                if tcp && proto == IPPROTO_TCP {
                                    let remote_opt = parse_sockaddr(&sockstat.sa_peer);
                                    let (remote_addr, remote_port, state) = if let Some(remote) = remote_opt {
                                        if remote.port() != 0 || !remote.ip().is_unspecified() {
                                            (remote.ip(), remote.port(), TcpState::Established)
                                        } else {
                                            let addr = if family == AF_INET {
                                                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                                            } else {
                                                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                                            };
                                            (addr, 0, TcpState::Listen)
                                        }
                                    } else {
                                        let addr = if family == AF_INET {
                                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                                        } else {
                                            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                                        };
                                        (addr, 0, TcpState::Listen)
                                    };

                                    results.push(Ok(SocketInfo {
                                        protocol_socket_info: ProtocolSocketInfo::Tcp(
                                            TcpSocketInfo {
                                                local_addr: local.ip(),
                                                local_port: local.port(),
                                                remote_addr,
                                                remote_port,
                                                state,
                                            },
                                        ),
                                        processes,
                                    }));
                                } else if udp && proto == IPPROTO_UDP {
                                    results.push(Ok(SocketInfo {
                                        protocol_socket_info: ProtocolSocketInfo::Udp(
                                            UdpSocketInfo {
                                                local_addr: local.ip(),
                                                local_port: local.port(),
                                            },
                                        ),
                                        processes,
                                    }));
                                }
                            }
                        }
                    }
                }

                current_file = fst.next.stqe_next;
            }

            procstat_freefiles(ps, files);
        }

        procstat_freeprocs(ps, procs);
        procstat_close(ps);
    }

    Ok(results.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netstat() {
        let ns: Vec<_> = iterate_netstat_info(AddressFamilyFlags::all(), ProtocolFlags::all())
            .unwrap()
            .collect();
        // Should find at least some sockets
        assert!(!ns.is_empty());
    }
}
