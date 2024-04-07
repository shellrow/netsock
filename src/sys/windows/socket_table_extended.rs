use super::proc::get_process_name;
use crate::error::*;
use crate::process::Process;
use crate::socket::{ProtocolSocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use crate::{socket::SocketInfo, sys::windows::ffi::*};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait SocketTable {
    fn get_table() -> Result<Vec<u8>, Error>;
    fn get_rows_count(table: &[u8]) -> usize;
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo;
}

impl SocketTable for MIB_TCPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(AF_INET)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        table.rows_count as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows_ptr = &table.rows[0] as *const MIB_TCPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.owning_pid).unwrap_or(String::from("Unknown"));
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.local_addr))),
                local_port: u16::from_be(row.local_port as u16),
                remote_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.remote_addr))),
                remote_port: u16::from_be(row.remote_port as u16),
                state: TcpState::from(row.state),
            }),
            processes: vec![Process {
                pid: row.owning_pid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_TCP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(AF_INET6)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        table.rows_count as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows_ptr = &table.rows[0] as *const MIB_TCP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.owning_pid).unwrap_or(String::from("Unknown"));
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V6(Ipv6Addr::from(row.local_addr)),
                // local_scope: Option::Some(row.local_scope_id),
                local_port: u16::from_be(row.local_port as u16),
                remote_addr: IpAddr::V6(Ipv6Addr::from(row.remote_addr)),
                // remote_scope: Option::Some(row.remote_scope_id),
                remote_port: u16::from_be(row.remote_port as u16),
                state: TcpState::from(row.state),
            }),
            processes: vec![Process {
                pid: row.owning_pid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_UDPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(AF_INET)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        table.rows_count as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows_ptr = &table.rows[0] as *const MIB_UDPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.owning_pid).unwrap_or(String::from("Unknown"));
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.local_addr))),
                local_port: u16::from_be(row.local_port as u16),
            }),
            processes: vec![Process {
                pid: row.owning_pid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_UDP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(AF_INET6)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        table.rows_count as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows_ptr = &table.rows[0] as *const MIB_UDP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.owning_pid).unwrap_or(String::from("Unknown"));
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V6(Ipv6Addr::from(row.local_addr)),
                // local_scope: Option::Some(row.local_scope_id),
                local_port: u16::from_be(row.local_port as u16),
            }),
            processes: vec![Process {
                pid: row.owning_pid,
                name: pname,
            }],
        }
    }
}

fn get_extended_tcp_table(address_family: ULONG) -> Result<Vec<u8>, Error> {
    let mut table_size: DWORD = 0;
    let mut err_code = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut table_size,
            FALSE,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    let mut table = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        table = Vec::<u8>::with_capacity(table_size as usize);
        err_code = unsafe {
            GetExtendedTcpTable(
                table.as_mut_ptr() as PVOID,
                &mut table_size,
                FALSE,
                address_family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        iterations += 1;
        if iterations > 100 {
            return Result::Err(Error::FailedToAllocateBuffer);
        }
    }
    if err_code == NO_ERROR {
        Ok(table)
    } else {
        Err(Error::FailedToGetTcpTable(err_code as i32))
    }
}

fn get_extended_udp_table(address_family: ULONG) -> Result<Vec<u8>, Error> {
    let mut table_size: DWORD = 0;
    let mut err_code = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut table_size,
            FALSE,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    let mut table = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        table = Vec::<u8>::with_capacity(table_size as usize);
        err_code = unsafe {
            GetExtendedUdpTable(
                table.as_mut_ptr() as PVOID,
                &mut table_size,
                FALSE,
                address_family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        iterations += 1;
        if iterations > 100 {
            return Result::Err(Error::FailedToAllocateBuffer);
        }
    }
    if err_code == NO_ERROR {
        Ok(table)
    } else {
        Err(Error::FailedToGetUdpTable(err_code as i32))
    }
}
