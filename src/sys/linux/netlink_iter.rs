use crate::error::*;
use crate::socket::{ProtocolSocketInfo, SocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use std::io;

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::inet::InetResponse;
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

pub struct NetlinkIterator {
    protocol: u8,
    recv_buf: Vec<u8>,
    socket: Socket,
    offset: usize,
    is_done: bool,
}

impl NetlinkIterator {
    pub fn new(family: u8, protocol: u8) -> Result<Self, Error> {
        let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let mut packet = NetlinkMessage::new(
            nl_hdr,
            SockDiagMessage::InetRequest(InetRequest {
                family,
                protocol,
                extensions: ExtensionFlags::empty(),
                states: StateFlags::all(),
                socket_id: if family == AF_INET6 {
                    SocketId::new_v6()
                } else {
                    SocketId::new_v4()
                },
            })
            .into(),
        );

        packet.finalize();

        let mut buf = vec![0; packet.buffer_len()];
        packet.serialize(&mut buf[..]);
        socket.send(&buf[..], 0)?;

        Ok(NetlinkIterator {
            protocol,
            socket,
            recv_buf: Vec::new(),
            offset: 0,
            is_done: false,
        })
    }

    fn try_read_next_packet(&mut self) -> Result<Option<SocketInfo>, Error> {
        if self.is_done {
            return Ok(None);
        }

        loop {
            if self.offset >= self.recv_buf.len() {
                let (data, sender) = loop {
                    match self.socket.recv_from_full() {
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        result => break result?,
                    }
                };
                if sender.port_number() != 0 {
                    continue;
                }
                self.recv_buf = data;
                self.offset = 0;
            }

            let packet =
                NetlinkMessage::<SockDiagMessage>::deserialize(&self.recv_buf[self.offset..])
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.offset += (packet.header.length as usize).next_multiple_of(4);
            if packet.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(
                    io::Error::new(io::ErrorKind::Interrupted, "netlink dump interrupted").into(),
                );
            }
            match packet.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    return Ok(Some(parse_diag_msg(&response, self.protocol)?));
                }
                NetlinkPayload::Done(done) => {
                    if done.code != 0 {
                        return Err(io::Error::from_raw_os_error(done.code.saturating_abs()).into());
                    }
                    self.is_done = true;
                    return Ok(None);
                }
                NetlinkPayload::Error(err) => {
                    if err.code.is_some() {
                        return Err(io::Error::from(err).into());
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected netlink dump response",
                    )
                    .into());
                }
            }
        }
    }
}

impl Iterator for NetlinkIterator {
    type Item = Result<SocketInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.try_read_next_packet();
        if result.is_err() {
            self.is_done = true;
        }
        result.transpose()
    }
}

fn parse_diag_msg(diag_msg: &InetResponse, protocol: u8) -> Result<SocketInfo, Error> {
    let src_port = diag_msg.header.socket_id.source_port;
    let dst_port = diag_msg.header.socket_id.destination_port;
    let src_ip = diag_msg.header.socket_id.source_address;
    let dst_ip = diag_msg.header.socket_id.destination_address;

    let sock_info = match protocol {
        IPPROTO_TCP => SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: src_ip,
                local_port: src_port,
                remote_addr: dst_ip,
                remote_port: dst_port,
                state: TcpState::from(diag_msg.header.state),
            }),
            processes: Vec::new(),
            inode: diag_msg.header.inode,
            uid: diag_msg.header.uid,
        },
        IPPROTO_UDP => SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: src_ip,
                local_port: src_port,
            }),
            processes: Vec::new(),
            inode: diag_msg.header.inode,
            uid: diag_msg.header.uid,
        },
        _ => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "unexpected socket protocol").into(),
            );
        }
    };

    Ok(sock_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::DoneMessage;

    #[test]
    fn interrupted_and_failed_dumps_report_one_error() {
        for (flags, code, kind) in [
            (NLM_F_DUMP_INTR, 0, io::ErrorKind::Interrupted),
            (0, -13, io::ErrorKind::PermissionDenied),
        ] {
            let mut header = NetlinkHeader::default();
            header.flags = flags;
            let mut done = DoneMessage::default();
            done.code = code;
            let mut packet =
                NetlinkMessage::<SockDiagMessage>::new(header, NetlinkPayload::Done(done));
            packet.finalize();
            let mut recv_buf = vec![0; packet.buffer_len()];
            packet.serialize(&mut recv_buf);
            let mut iterator = NetlinkIterator {
                protocol: IPPROTO_TCP,
                recv_buf,
                socket: Socket::new(NETLINK_SOCK_DIAG).unwrap(),
                offset: 0,
                is_done: false,
            };
            assert!(matches!(iterator.next(), Some(Err(Error::OsError(e))) if e.kind() == kind));
            assert!(iterator.next().is_none());
        }
    }
}
