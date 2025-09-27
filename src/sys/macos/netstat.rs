use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libproc::file_info::{ListFDs, ProcFDInfo, ProcFDType, pidfdinfo};
use libproc::net_info::SocketFDInfo;
use libproc::proc_pid::{listpidinfo, pidinfo};
use libproc::processes::ProcFilter;
use libproc::task_info::TaskAllInfo;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::socket::{ProtocolSocketInfo, SocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;

use super::proc::get_process_name;

type PID = u32;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

// Adapter from proc_info.h
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, FromPrimitive)]
enum SockInfo {
    Generic = 0,
    In = 1,
    Tcp = 2,
    Un = 3,
    Ndrv = 4,
    Kern_event = 5,
    Kern_ctl = 6,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, FromPrimitive)]
enum SocketFamily {
    AF_UNSPEC = 0,
    /* unspecified */
    AF_UNIX = 1,
    /* local to host (pipes) */
    AF_INET = 2,
    /* internetwork: UDP, TCP, etc. */
    AF_IMPLINK = 3,
    /* arpanet imp addresses */
    AF_PUP = 4,
    /* pup protocols: e.g. BSP */
    AF_CHAOS = 5,
    /* mit CHAOS protocols */
    AF_NS = 6,
    /* XEROX NS protocols */
    AF_ISO = 7,
    /* ISO protocols */
    AF_ECMA = 8,
    /* European computer manufacturers */
    AF_DATAKIT = 9,
    /* datakit protocols */
    AF_CCITT = 10,
    /* CCITT protocols, X.25 etc */
    AF_SNA = 11,
    /* IBM SNA */
    AF_DECnet = 12,
    /* DECnet */
    AF_DLI = 13,
    /* DEC Direct data link interface */
    AF_LAT = 14,
    /* LAT */
    AF_HYLINK = 15,
    /* NSC Hyperchannel */
    AF_APPLETALK = 16,
    /* Apple Talk */
    AF_ROUTE = 17,
    /* Internal Routing Protocol */
    AF_LINK = 18,
    /* Link layer interface */
    pseudo_AF_XTP = 19,
    /* eXpress Transfer Protocol (no AF) */
    AF_COIP = 20,
    /* connection-oriented IP, aka ST II */
    AF_CNT = 21,
    /* Computer Network Technology */
    pseudo_AF_RTIP = 22,
    /* Help Identify RTIP packets */
    AF_IPX = 23,
    /* Novell Internet Protocol */
    AF_SIP = 24,
    /* Simple Internet Protocol */
    pseudo_AF_PIP = 25,
    /* Help Identify PIP packets */
    AF_NDRV = 27,
    /* Network Driver 'raw' access */
    AF_ISDN = 28,
    /* Integrated Services Digital Network */
    pseudo_AF_KEY = 29,
    /* Internal key-management function */
    AF_INET6 = 30,
    /* IPv6 */
    AF_NATM = 31,
    /* native ATM access */
    AF_SYSTEM = 32,
    /* Kernel event messages */
    AF_NETBIOS = 33,
    /* NetBIOS */
    AF_PPP = 34,
    /* PPP communication protocol */
    pseudo_AF_HDRCMPLT = 35,
    /* Used by BPF to not rewrite headers output routine */
    AF_RESERVED_36 = 36,
    /* Reserved for internal usage */
    AF_IEEE80211 = 37,
    /* IEEE 802.11 protocol */
    AF_UTUN = 38,
    AF_MAX = 40,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, FromPrimitive)]
enum TCPSocketState {
    CLOSED = 0,
    /* closed */
    LISTEN = 1,
    /* listening for connection */
    SYN_SENT = 2,
    /* active, have sent syn */
    SYN_RECEIVED = 3,
    /* have send and received syn */
    ESTABLISHED = 4,
    /* established */
    CLOSE_WAIT = 5,
    /* rcvd fin, waiting for close */
    FIN_WAIT_1 = 6,
    /* have closed, sent fin */
    CLOSING = 7,
    /* closed xchd FIN; await FIN ACK */
    LAST_ACK = 8,
    /* had fin and close; await FIN ACK */
    FIN_WAIT_2 = 9,
    /* have closed, fin is acked */
    TIME_WAIT = 10,
    /* in 2*msl quiet wait after close */
}

impl From<TCPSocketState> for TcpState {
    fn from(s: TCPSocketState) -> Self {
        match s {
            TCPSocketState::CLOSED => TcpState::Closed,
            TCPSocketState::LISTEN => TcpState::Listen,
            TCPSocketState::SYN_SENT => TcpState::SynSent,
            TCPSocketState::SYN_RECEIVED => TcpState::SynReceived,
            TCPSocketState::ESTABLISHED => TcpState::Established,
            TCPSocketState::CLOSE_WAIT => TcpState::CloseWait,
            TCPSocketState::FIN_WAIT_1 => TcpState::FinWait1,
            TCPSocketState::CLOSING => TcpState::Closing,
            TCPSocketState::LAST_ACK => TcpState::LastAck,
            TCPSocketState::FIN_WAIT_2 => TcpState::FinWait2,
            TCPSocketState::TIME_WAIT => TcpState::TimeWait,
        }
    }
}

pub fn list_pids(proc_filter: ProcFilter) -> Result<Vec<PID>, Error> {
    libproc::processes::pids_by_type(proc_filter).map_err(|e| Error::FailedToListProcesses(e))
}

pub fn list_all_fds_for_pid(pid: PID) -> Result<Vec<ProcFDInfo>, Error> {
    let pid_info = pidinfo::<TaskAllInfo>(pid as i32, 0).map_err(|e| {
        Error::FailedToQueryFileDescriptors(io::Error::new(io::ErrorKind::Other, e))
    })?;
    let fds = listpidinfo::<ListFDs>(pid as i32, pid_info.pbsd.pbi_nfiles as usize)
        .map_err(|e| Error::FailedToQueryFileDescriptors(io::Error::new(io::ErrorKind::Other, e)))?
        .into_iter()
        .collect();
    Ok(fds)
}

pub fn get_fd_information(pid: PID, fd: ProcFDInfo) -> Result<SocketFDInfo, Error> {
    let socket = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd).map_err(|e| {
        Error::FailedToQueryFileDescriptors(io::Error::new(io::ErrorKind::Other, e))
    })?;
    Ok(socket)
}

fn get_local_addr(
    family: SocketFamily,
    in_sock_info: libproc::net_info::InSockInfo,
) -> Result<IpAddr, Error> {
    // Unsafe because of union access, but we check the type of address before accessing.
    match family {
        SocketFamily::AF_INET => {
            let addr = unsafe { in_sock_info.insi_laddr.ina_46.i46a_addr4.s_addr };
            Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr))))
        }
        SocketFamily::AF_INET6 => {
            let octets = unsafe { in_sock_info.insi_laddr.ina_6.s6_addr };
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(Error::UnsupportedSocketFamily(family as u32)),
    }
}

fn get_remote_addr(
    family: SocketFamily,
    in_sock_info: libproc::net_info::InSockInfo,
) -> Result<IpAddr, Error> {
    // Unsafe because of union access, but we check the type of address before accessing.
    match family {
        SocketFamily::AF_INET => {
            let addr = unsafe { in_sock_info.insi_faddr.ina_46.i46a_addr4.s_addr };
            Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr))))
        }
        SocketFamily::AF_INET6 => {
            let octets = unsafe { in_sock_info.insi_faddr.ina_6.s6_addr };
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(Error::UnsupportedSocketFamily(family as u32)),
    }
}

fn parse_tcp_socket_info(sinfo: SocketFDInfo) -> Option<TcpSocketInfo> {
    let sock_info = sinfo.psi;
    let family = match SocketFamily::from_i32(sock_info.soi_family) {
        Some(family) => family,
        None => return None,
    };
    let socket_kind = SockInfo::from_i32(sock_info.soi_kind)?;

    // Access to union field in unsafe, but we already checked that this is a TCP connection.
    if socket_kind != SockInfo::Tcp {
        return None;
    }
    let tcp_in = unsafe { sock_info.soi_proto.pri_tcp };

    let tcp_sockaddr_in = tcp_in.tcpsi_ini;

    let connection_state = TCPSocketState::from_i32(tcp_in.tcpsi_state)?;
    let remote_address = get_remote_addr(family, tcp_sockaddr_in).ok()?;
    let local_address = get_local_addr(family, tcp_sockaddr_in).ok()?;

    let lport = u16::from_be(tcp_sockaddr_in.insi_lport as u16);
    let fport = u16::from_be(tcp_sockaddr_in.insi_fport as u16);

    let socket_info = TcpSocketInfo {
        local_addr: local_address,
        local_port: lport,
        remote_addr: remote_address,
        remote_port: fport,
        state: connection_state.into(),
    };

    Some(socket_info)
}

fn parse_udp_socket_info(sinfo: SocketFDInfo) -> Option<UdpSocketInfo> {
    let sock_info = sinfo.psi;
    let family = match SocketFamily::from_i32(sock_info.soi_family) {
        Some(family) => family,
        None => return None,
    };
    let socket_kind = SockInfo::from_i32(sock_info.soi_kind)?;

    // Access to union field in unsafe, but we already checked that this is a In connection.
    if socket_kind != SockInfo::In {
        return None;
    }
    let in_socket_info = unsafe { sock_info.soi_proto.pri_in };

    let local_address = get_local_addr(family, in_socket_info).ok()?;

    let lport = u16::from_be(in_socket_info.insi_lport as u16);

    let sock_info = UdpSocketInfo {
        local_addr: local_address,
        local_port: lport,
    };

    Some(sock_info)
}

pub fn iterate_netstat_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
    let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);

    let pids = list_pids(ProcFilter::All)?;

    let mut results = vec![];

    for pid in pids {
        // This will fail on PermissionDenied if we are not sufficiently privileged.
        // We do not return on a specific pid failure,
        // since some of them may fail randomly (unexpectedly closed etc..)
        let fds = match list_all_fds_for_pid(pid) {
            Ok(fds) => fds,
            Err(_e) => {
                //results.push(Err(e));
                continue;
            }
        };

        let pname = match get_process_name(pid as i32) {
            Ok(pname) => pname,
            Err(_) => String::from("Unknown"),
        };

        for fd in fds {
            let proc_fdtype: ProcFDType = fd.proc_fdtype.into();
            match proc_fdtype {
                ProcFDType::Socket => {
                    let sock_fd_info = match get_fd_information(pid, fd) {
                        Ok(fd_info) => fd_info,
                        Err(e) => {
                            results.push(Err(e));
                            continue;
                        }
                    };

                    /* let sock_info_kind: SocketInfoKind = sock_fd_info.psi.soi_kind.into();
                    match sock_info_kind {
                        SocketInfoKind::In | SocketInfoKind::Tcp  => {
                            // TODO: Handle more socket kinds if needed
                        },
                        _ => {},
                    } */

                    if (ipv4 && sock_fd_info.psi.soi_family == AF_INET as i32)
                        || (ipv6 && sock_fd_info.psi.soi_family == AF_INET6 as i32)
                    {
                        if tcp && sock_fd_info.psi.soi_protocol == IPPROTO_TCP as i32 {
                            if let Some(row) = parse_tcp_socket_info(sock_fd_info) {
                                results.push(Ok(SocketInfo {
                                    protocol_socket_info: ProtocolSocketInfo::Tcp(row),
                                    processes: vec![Process {
                                        pid: pid as u32,
                                        name: pname.clone(),
                                    }],
                                }));
                            }
                        } else if udp && sock_fd_info.psi.soi_protocol == IPPROTO_UDP as i32 {
                            if let Some(row) = parse_udp_socket_info(sock_fd_info) {
                                results.push(Ok(SocketInfo {
                                    protocol_socket_info: ProtocolSocketInfo::Udp(row),
                                    processes: vec![Process {
                                        pid: pid as u32,
                                        name: pname.clone(),
                                    }],
                                }));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(results.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_pids() {
        assert!(list_pids(ProcFilter::All).unwrap().len() > 5);
    }

    #[test]
    fn test_list_fds_for_pid() {
        let pids = list_pids(ProcFilter::All).unwrap();
        for pid in pids.iter().take(100) {
            if let Ok(fds) = list_all_fds_for_pid(*pid) {
                assert!(!fds.is_empty());
            }
        }
    }

    #[test]
    fn test_netstat() {
        let ns: Vec<_> = iterate_netstat_info(AddressFamilyFlags::all(), ProtocolFlags::all())
            .unwrap()
            .collect();
        assert!(!ns.is_empty());
    }
}
