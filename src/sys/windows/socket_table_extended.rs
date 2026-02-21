use super::proc::get_process_name;
use crate::error::*;
use crate::process::Process;
use crate::socket::SocketInfo;
use crate::socket::{ProtocolSocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

pub trait SocketTable {
    fn get_table() -> Result<Vec<u8>, Error>;
    fn get_rows_count(table: &[u8]) -> usize;
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo;
}

impl SocketTable for MIB_TCPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(AF_INET as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_TCPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.dwOwningPid).unwrap_or_else(|_| "Unknown".into());
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                local_port: u16::from_be(row.dwLocalPort as u16),
                remote_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr))),
                remote_port: u16::from_be(row.dwRemotePort as u16),
                state: TcpState::from(row.dwState),
            }),
            processes: vec![Process {
                pid: row.dwOwningPid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_TCP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(AF_INET6 as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_TCP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.dwOwningPid).unwrap_or_else(|_| "Unknown".into());
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                // local_scope: Option::Some(row.dwLocalScopeId),
                local_port: u16::from_be(row.dwLocalPort as u16),
                remote_addr: IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                // remote_scope: Option::Some(row.dwRemoteScopeId),
                remote_port: u16::from_be(row.dwRemotePort as u16),
                state: TcpState::from(row.dwState),
            }),
            processes: vec![Process {
                pid: row.dwOwningPid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_UDPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(AF_INET as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_UDPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.dwOwningPid).unwrap_or_else(|_| "Unknown".into());
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                local_port: u16::from_be(row.dwLocalPort as u16),
            }),
            processes: vec![Process {
                pid: row.dwOwningPid,
                name: pname,
            }],
        }
    }
}

impl SocketTable for MIB_UDP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(AF_INET6 as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_UDP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        let pname = get_process_name(row.dwOwningPid).unwrap_or_else(|_| "Unknown".into());
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                // local_scope: Option::Some(row.dwLocalScopeId),
                local_port: u16::from_be(row.dwLocalPort as u16),
            }),
            processes: vec![Process {
                pid: row.dwOwningPid,
                name: pname,
            }],
        }
    }
}

fn get_extended_tcp_table(address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size: u32 = 0;
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
                table.as_mut_ptr() as *mut _,
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
        unsafe { table.set_len(table_size as usize) };
        Ok(table)
    } else {
        Err(Error::FailedToGetTcpTable(err_code as i32))
    }
}

fn get_extended_udp_table(address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size: u32 = 0;
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
                table.as_mut_ptr() as *mut _,
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
        unsafe { table.set_len(table_size as usize) };
        Ok(table)
    } else {
        Err(Error::FailedToGetUdpTable(err_code as i32))
    }
}
