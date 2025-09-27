use crate::error::*;
use crate::socket::SocketInfo;
use crate::socket::{ProtocolSocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use crate::sys::windows::socket_table_extended::SocketTable;
use std::net::{IpAddr, Ipv4Addr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetTcpTable, GetUdpTable, MIB_TCPROW_LH, MIB_TCPTABLE, MIB_UDPROW, MIB_UDPTABLE,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

impl SocketTable for MIB_TCPTABLE {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_tcp_table(AF_INET as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE) };
        let rows_ptr = &table.table[0] as *const MIB_TCPROW_LH;
        let row = unsafe { &*rows_ptr.add(index) };
        let dw_state = unsafe { row.Anonymous.dwState };
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                local_port: u16::from_be(row.dwLocalPort as u16),
                remote_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr))),
                remote_port: u16::from_be(row.dwRemotePort as u16),
                state: TcpState::from(dw_state),
            }),
            processes: vec![],
        }
    }
}

impl SocketTable for MIB_UDPTABLE {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_udp_table(AF_INET as u32)
    }
    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE) };
        table.dwNumEntries as usize
    }
    fn get_socket_info(table: &[u8], index: usize) -> SocketInfo {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE) };
        let rows_ptr = &table.table[0] as *const MIB_UDPROW;
        let row = unsafe { &*rows_ptr.add(index) };
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                local_port: u16::from_be(row.dwLocalPort as u16),
            }),
            processes: vec![],
        }
    }
}

fn get_tcp_table(_address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size: u32 = 0;
    let mut err_code = unsafe { GetTcpTable(std::ptr::null_mut(), &mut table_size, FALSE) };
    let mut table = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        table = Vec::<u8>::with_capacity(table_size as usize);
        err_code = unsafe { GetTcpTable(table.as_mut_ptr() as *mut _, &mut table_size, FALSE) };
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

fn get_udp_table(_address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size: u32 = 0;
    let mut err_code = unsafe { GetUdpTable(std::ptr::null_mut(), &mut table_size, FALSE) };
    let mut table = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        table = Vec::<u8>::with_capacity(table_size as usize);
        err_code = unsafe { GetUdpTable(table.as_mut_ptr() as *mut _, &mut table_size, FALSE) };
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
