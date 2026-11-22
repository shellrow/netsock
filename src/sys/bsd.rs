use crate::family::AddressFamilyFlags;
use crate::protocol::ProtocolFlags;
use crate::socket::{ProtocolSocketInfo, SocketInfo, TcpSocketInfo, UdpSocketInfo};
use crate::state::TcpState;
use std::net::{IpAddr, Ipv4Addr};

/// Matches the private C interface in bsd.h.
#[repr(C)]
#[derive(Default)]
pub(super) struct SocketRow {
    pub id: u64,
    pub(super) local: [u8; 16],
    pub(super) remote: [u8; 16],
    pub(super) local_port: u16,
    pub(super) remote_port: u16,
    state: i32,
    pub(super) ipv6: u8,
    pub(super) tcp: u8,
}

impl SocketRow {
    pub fn matches(&self, families: AddressFamilyFlags, protocols: ProtocolFlags) -> bool {
        families.contains(if self.ipv6 != 0 {
            AddressFamilyFlags::IPV6
        } else {
            AddressFamilyFlags::IPV4
        }) && protocols.contains(if self.tcp != 0 {
            ProtocolFlags::TCP
        } else {
            ProtocolFlags::UDP
        })
    }

    fn address(&self, mut bytes: [u8; 16]) -> IpAddr {
        if self.ipv6 == 0 {
            return Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into();
        }
        // BSD kernels embed the interface index in link-local addresses.
        if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
            bytes[2..4].fill(0);
        }
        bytes.into()
    }

    pub fn socket_info(&self) -> SocketInfo {
        let local_addr = self.address(self.local);
        let local_port = self.local_port;
        let protocol_socket_info = if self.tcp != 0 {
            ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr,
                local_port,
                remote_addr: self.address(self.remote),
                remote_port: self.remote_port,
                state: match self.state {
                    0 => TcpState::Closed,
                    1 => TcpState::Listen,
                    2 => TcpState::SynSent,
                    3 => TcpState::SynReceived,
                    4 => TcpState::Established,
                    5 => TcpState::CloseWait,
                    6 => TcpState::FinWait1,
                    7 => TcpState::Closing,
                    8 => TcpState::LastAck,
                    9 => TcpState::FinWait2,
                    10 => TcpState::TimeWait,
                    _ => TcpState::Unknown,
                },
            })
        } else {
            ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr,
                local_port,
            })
        };
        SocketInfo {
            protocol_socket_info,
            processes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn strips_embedded_interface_index_from_link_local_addresses() {
        let row = SocketRow {
            ipv6: 1,
            ..Default::default()
        };
        for (input, expected) in [("fe80:7::1", "fe80::1"), ("2001:db8:7::1", "2001:db8:7::1")] {
            let bytes = input.parse::<Ipv6Addr>().unwrap().octets();
            assert_eq!(row.address(bytes), expected.parse::<IpAddr>().unwrap());
        }
    }
}
