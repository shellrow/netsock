use super::proc::get_process_names;
use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::socket::{ProtocolSocketInfo, SocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

fn load_table(mut load: impl FnMut(*mut c_void, &mut u32) -> u32) -> Result<Vec<u32>, Error> {
    let mut words = Vec::<u32>::new();
    let mut bytes = 0;
    for _ in 0..16 {
        let ptr = if words.is_empty() {
            std::ptr::null_mut()
        } else {
            words.as_mut_ptr().cast()
        };
        match load(ptr, &mut bytes) {
            NO_ERROR => {
                if bytes as usize > size_of_val(&words[..]) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IP Helper returned an oversized table",
                    )
                    .into());
                }
                words.truncate(bytes as usize / size_of::<u32>());
                return Ok(words);
            }
            ERROR_INSUFFICIENT_BUFFER => {
                let needed = (bytes as usize).div_ceil(size_of::<u32>());
                words
                    .try_reserve(needed.saturating_sub(words.len()))
                    .map_err(io::Error::other)?;
                words.resize(needed, 0);
            }
            code => return Err(io::Error::from_raw_os_error(code as i32).into()),
        }
    }
    Err(io::Error::new(io::ErrorKind::WouldBlock, "socket table kept growing").into())
}

// Each call supplies the integer-only MIB row type and offset for the table
// class passed to IP Helper. The table may contain just a count and zero rows.
unsafe fn rows<T: Copy>(
    words: &[u32],
    offset: usize,
) -> Result<impl Iterator<Item = T> + '_, Error> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid IP Helper table length");
    let count = *words.first().ok_or_else(invalid)? as usize;
    let available = size_of_val(words).checked_sub(offset).ok_or_else(invalid)?;
    if count > available / size_of::<T>() {
        return Err(invalid().into());
    }
    Ok((0..count).map(move |index| unsafe {
        words
            .as_ptr()
            .byte_add(offset + index * size_of::<T>())
            .cast::<T>()
            .read_unaligned()
    }))
}

fn tcp(
    local_addr: IpAddr,
    local: u32,
    remote_addr: IpAddr,
    remote: u32,
    state: u32,
) -> ProtocolSocketInfo {
    let state = TcpState::from(state);
    let (remote_addr, remote_port) = if state == TcpState::Listen {
        // The remote fields are undefined for listening rows.
        let unspecified = if local_addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        (unspecified, 0)
    } else {
        (remote_addr, u16::from_be(remote as u16))
    };
    ProtocolSocketInfo::Tcp(TcpSocketInfo {
        local_addr,
        local_port: u16::from_be(local as u16),
        remote_addr,
        remote_port,
        state,
    })
}

fn udp(local_addr: IpAddr, port: u32) -> ProtocolSocketInfo {
    ProtocolSocketInfo::Udp(UdpSocketInfo {
        local_addr,
        local_port: u16::from_be(port as u16),
    })
}

pub(super) fn enumerate(
    families: AddressFamilyFlags,
    protocols: ProtocolFlags,
    with_owners: bool,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let mut sockets = Vec::new();
    let names = (with_owners
        && families.intersects(AddressFamilyFlags::all())
        && protocols.intersects(ProtocolFlags::all()))
    .then(|| get_process_names().unwrap_or_default());
    let mut add = |protocol_socket_info, pid| {
        let processes = match &names {
            Some(names) if pid != 0 => vec![Process {
                pid,
                name: names.get(&pid).cloned().unwrap_or_default(),
            }],
            _ => Vec::new(),
        };
        sockets.push(Ok(SocketInfo {
            protocol_socket_info,
            processes,
        }));
    };
    for (flag, family) in [
        (AddressFamilyFlags::IPV4, AF_INET),
        (AddressFamilyFlags::IPV6, AF_INET6),
    ] {
        if !families.contains(flag) {
            continue;
        }
        if protocols.contains(ProtocolFlags::TCP) {
            let table = load_table(|buf, len| unsafe {
                GetExtendedTcpTable(buf, len, FALSE, family.into(), TCP_TABLE_OWNER_PID_ALL, 0)
            })?;
            if family == AF_INET {
                for row in unsafe {
                    rows::<MIB_TCPROW_OWNER_PID>(&table, offset_of!(MIB_TCPTABLE_OWNER_PID, table))?
                } {
                    add(
                        tcp(
                            row.dwLocalAddr.to_ne_bytes().into(),
                            row.dwLocalPort,
                            row.dwRemoteAddr.to_ne_bytes().into(),
                            row.dwRemotePort,
                            row.dwState,
                        ),
                        row.dwOwningPid,
                    );
                }
            } else {
                for row in unsafe {
                    rows::<MIB_TCP6ROW_OWNER_PID>(
                        &table,
                        offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
                    )?
                } {
                    add(
                        tcp(
                            row.ucLocalAddr.into(),
                            row.dwLocalPort,
                            row.ucRemoteAddr.into(),
                            row.dwRemotePort,
                            row.dwState,
                        ),
                        row.dwOwningPid,
                    );
                }
            }
        }
        if protocols.contains(ProtocolFlags::UDP) {
            let table = load_table(|buf, len| unsafe {
                GetExtendedUdpTable(buf, len, FALSE, family.into(), UDP_TABLE_OWNER_PID, 0)
            })?;
            if family == AF_INET {
                for row in unsafe {
                    rows::<MIB_UDPROW_OWNER_PID>(&table, offset_of!(MIB_UDPTABLE_OWNER_PID, table))?
                } {
                    add(
                        udp(row.dwLocalAddr.to_ne_bytes().into(), row.dwLocalPort),
                        row.dwOwningPid,
                    );
                }
            } else {
                for row in unsafe {
                    rows::<MIB_UDP6ROW_OWNER_PID>(
                        &table,
                        offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
                    )?
                } {
                    add(
                        udp(row.ucLocalAddr.into(), row.dwLocalPort),
                        row.dwOwningPid,
                    );
                }
            }
        }
    }
    Ok(sockets.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_tables_and_rejects_incomplete_rows() {
        let offset = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        assert_eq!(
            unsafe { rows::<MIB_TCPROW_OWNER_PID>(&[0], offset) }
                .unwrap()
                .count(),
            0
        );
        assert!(unsafe { rows::<MIB_TCPROW_OWNER_PID>(&[1], offset) }.is_err());
    }
}
