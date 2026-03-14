use crate::error::Error;
use crate::family::AddressFamilyFlags;
use crate::process::Process;
use crate::protocol::ProtocolFlags;
use crate::state::TcpState;
use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Socket metadata and optional owning process information.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SocketInfo {
    /// Protocol-specific fields.
    pub protocol_socket_info: ProtocolSocketInfo,
    /// Processes currently associated with the socket.
    pub processes: Vec<Process>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Socket inode on Linux/Android.
    pub inode: u32,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Owning user ID on Linux/Android.
    pub uid: u32,
}

/// Protocol-specific socket details.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtocolSocketInfo {
    /// TCP socket details, including state and endpoints.
    Tcp(TcpSocketInfo),
    /// UDP socket details.
    Udp(UdpSocketInfo),
}

/// TCP socket fields.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpSocketInfo {
    /// Local IP address.
    pub local_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
    /// Remote IP address.
    pub remote_addr: IpAddr,
    /// Remote port.
    pub remote_port: u16,
    /// Current TCP state.
    pub state: TcpState,
}

/// UDP socket fields.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UdpSocketInfo {
    /// Local IP address.
    pub local_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
}

impl SocketInfo {
    /// Returns `true` when the socket contains TCP-specific information.
    pub fn is_tcp(&self) -> bool {
        matches!(self.protocol_socket_info, ProtocolSocketInfo::Tcp(_))
    }

    /// Returns `true` when the socket contains UDP-specific information.
    pub fn is_udp(&self) -> bool {
        matches!(self.protocol_socket_info, ProtocolSocketInfo::Udp(_))
    }

    /// Returns the local IP address for either TCP or UDP sockets.
    pub fn local_addr(&self) -> IpAddr {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => s.local_addr,
            ProtocolSocketInfo::Udp(s) => s.local_addr,
        }
    }

    /// Returns the local port for either TCP or UDP sockets.
    pub fn local_port(&self) -> u16 {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => s.local_port,
            ProtocolSocketInfo::Udp(s) => s.local_port,
        }
    }

    /// Returns the remote IP address for TCP sockets.
    pub fn remote_addr(&self) -> Option<IpAddr> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => Some(s.remote_addr),
            ProtocolSocketInfo::Udp(_) => None,
        }
    }

    /// Returns the remote port for TCP sockets.
    pub fn remote_port(&self) -> Option<u16> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => Some(s.remote_port),
            ProtocolSocketInfo::Udp(_) => None,
        }
    }

    /// Returns the TCP socket details when available.
    pub fn tcp_info(&self) -> Option<&TcpSocketInfo> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(info) => Some(info),
            ProtocolSocketInfo::Udp(_) => None,
        }
    }

    /// Returns the UDP socket details when available.
    pub fn udp_info(&self) -> Option<&UdpSocketInfo> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => None,
            ProtocolSocketInfo::Udp(info) => Some(info),
        }
    }

    /// Returns `true` if any associated process has the given PID.
    pub fn is_owned_by_pid(&self, pid: u32) -> bool {
        self.processes.iter().any(|process| process.pid == pid)
    }

    fn matches_protocol_flags(&self, flags: ProtocolFlags) -> bool {
        match self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => flags.contains(ProtocolFlags::TCP),
            ProtocolSocketInfo::Udp(_) => flags.contains(ProtocolFlags::UDP),
        }
    }

    fn matches_address_family_flags(&self, flags: AddressFamilyFlags) -> bool {
        match self.local_addr() {
            IpAddr::V4(_) => flags.contains(AddressFamilyFlags::IPV4),
            IpAddr::V6(_) => flags.contains(AddressFamilyFlags::IPV6),
        }
    }
}

/// Describes criteria that can be used to filter [`SocketInfo`] values.
#[derive(Clone, Debug, Default)]
pub struct SocketQuery {
    protocol_flags: Option<ProtocolFlags>,
    address_family_flags: Option<AddressFamilyFlags>,
    local_addr: Option<IpAddr>,
    local_port: Option<u16>,
    remote_addr: Option<IpAddr>,
    remote_port: Option<u16>,
    tcp_state: Option<TcpState>,
    owner_pid: Option<u32>,
    process_name: Option<String>,
}

impl SocketQuery {
    /// Creates an empty query that matches all sockets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters sockets to those matching at least one of the specified protocols.
    pub fn with_protocol_flags(mut self, flags: ProtocolFlags) -> Self {
        self.protocol_flags = Some(flags);
        self
    }

    /// Filters sockets to those matching at least one of the specified address families.
    pub fn with_address_family_flags(mut self, flags: AddressFamilyFlags) -> Self {
        self.address_family_flags = Some(flags);
        self
    }

    /// Filters sockets to those bound to the specified local IP address.
    pub fn with_local_addr(mut self, addr: IpAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    /// Filters sockets to those bound to the specified local port.
    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    /// Filters sockets to those connected to the specified remote IP address.
    pub fn with_remote_addr(mut self, addr: IpAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Filters sockets to those connected to the specified remote port.
    pub fn with_remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    /// Filters TCP sockets to those in the specified state.
    pub fn with_tcp_state(mut self, state: TcpState) -> Self {
        self.tcp_state = Some(state);
        self
    }

    /// Filters sockets to those owned by the specified PID.
    pub fn with_owner_pid(mut self, pid: u32) -> Self {
        self.owner_pid = Some(pid);
        self
    }

    /// Filters sockets to those associated with the specified process name.
    pub fn with_process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Returns `true` when the socket satisfies all configured criteria.
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        if let Some(flags) = self.protocol_flags
            && !socket.matches_protocol_flags(flags)
        {
            return false;
        }

        if let Some(flags) = self.address_family_flags
            && !socket.matches_address_family_flags(flags)
        {
            return false;
        }

        if let Some(addr) = self.local_addr
            && socket.local_addr() != addr
        {
            return false;
        }

        if let Some(port) = self.local_port
            && socket.local_port() != port
        {
            return false;
        }

        if let Some(addr) = self.remote_addr
            && socket.remote_addr() != Some(addr)
        {
            return false;
        }

        if let Some(port) = self.remote_port
            && socket.remote_port() != Some(port)
        {
            return false;
        }

        if let Some(state) = self.tcp_state
            && socket.tcp_info().map(|info| info.state) != Some(state)
        {
            return false;
        }

        if let Some(pid) = self.owner_pid
            && !socket.is_owned_by_pid(pid)
        {
            return false;
        }

        if let Some(name) = &self.process_name
            && !socket.processes.iter().any(|process| &process.name == name)
        {
            return false;
        }

        true
    }
}

/// Extension helpers for iterators of `Result<SocketInfo, Error>`.
pub trait SocketIteratorExt: Iterator<Item = Result<SocketInfo, Error>> + Sized {
    /// Filters sockets using the provided [`SocketQuery`].
    fn filter_by_query(self, query: SocketQuery) -> FilterByQuery<Self> {
        FilterByQuery { inner: self, query }
    }
}

impl<I> SocketIteratorExt for I where I: Iterator<Item = Result<SocketInfo, Error>> + Sized {}

/// Iterator adapter returned by [`SocketIteratorExt::filter_by_query`].
pub struct FilterByQuery<I> {
    inner: I,
    query: SocketQuery,
}

impl<I> Iterator for FilterByQuery<I>
where
    I: Iterator<Item = Result<SocketInfo, Error>>,
{
    type Item = Result<SocketInfo, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        for item in self.inner.by_ref() {
            match item {
                Ok(socket) => {
                    if self.query.matches(&socket) {
                        return Some(Ok(socket));
                    }
                }
                Err(err) => return Some(Err(err)),
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn tcp_socket() -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 8080,
                remote_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)),
                remote_port: 443,
                state: TcpState::Established,
            }),
            processes: vec![Process {
                pid: 42,
                name: "demo".into(),
            }],
            #[cfg(any(target_os = "linux", target_os = "android"))]
            inode: 1,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            uid: 1000,
        }
    }

    fn udp_socket() -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 5353,
            }),
            processes: vec![Process {
                pid: 7,
                name: "resolver".into(),
            }],
            #[cfg(any(target_os = "linux", target_os = "android"))]
            inode: 2,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            uid: 1001,
        }
    }

    #[test]
    fn socket_info_helpers_expose_tcp_details() {
        let socket = tcp_socket();

        assert!(socket.is_tcp());
        assert!(!socket.is_udp());
        assert_eq!(socket.tcp_info().map(|info| info.local_port), Some(8080));
        assert_eq!(socket.udp_info(), None);
    }

    #[test]
    fn socket_info_helpers_expose_udp_details() {
        let socket = udp_socket();

        assert!(socket.is_udp());
        assert!(!socket.is_tcp());
        assert_eq!(socket.udp_info().map(|info| info.local_port), Some(5353));
        assert_eq!(socket.tcp_info(), None);
        assert_eq!(socket.remote_addr(), None);
        assert_eq!(socket.remote_port(), None);
    }

    #[test]
    fn socket_query_matches_protocol_family_and_tcp_state() {
        let socket = tcp_socket();
        let query = SocketQuery::new()
            .with_protocol_flags(ProtocolFlags::TCP)
            .with_address_family_flags(AddressFamilyFlags::IPV4)
            .with_tcp_state(TcpState::Established);

        assert!(query.matches(&socket));
    }

    #[test]
    fn socket_query_rejects_mismatched_protocol_family_and_state() {
        let socket = udp_socket();

        assert!(
            !SocketQuery::new()
                .with_protocol_flags(ProtocolFlags::TCP)
                .matches(&socket)
        );
        assert!(
            !SocketQuery::new()
                .with_address_family_flags(AddressFamilyFlags::IPV6)
                .matches(&socket)
        );
        assert!(
            !SocketQuery::new()
                .with_tcp_state(TcpState::Established)
                .matches(&socket)
        );
    }

    #[test]
    fn socket_query_matches_process_name() {
        let socket = udp_socket();

        assert!(
            SocketQuery::new()
                .with_process_name("resolver")
                .matches(&socket)
        );
        assert!(
            !SocketQuery::new()
                .with_process_name("other")
                .matches(&socket)
        );
    }
}
