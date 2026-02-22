use crate::error::Error;
use crate::process::Process;
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

    /// Returns `true` if any associated process has the given PID.
    pub fn is_owned_by_pid(&self, pid: u32) -> bool {
        self.processes.iter().any(|process| process.pid == pid)
    }
}

/// Describes criteria that can be used to filter [`SocketInfo`] values.
#[derive(Clone, Debug, Default)]
pub struct SocketQuery {
    local_addr: Option<IpAddr>,
    local_port: Option<u16>,
    remote_addr: Option<IpAddr>,
    remote_port: Option<u16>,
    owner_pid: Option<u32>,
}

impl SocketQuery {
    /// Creates an empty query that matches all sockets.
    pub fn new() -> Self {
        Self::default()
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

    /// Filters sockets to those owned by the specified PID.
    pub fn with_owner_pid(mut self, pid: u32) -> Self {
        self.owner_pid = Some(pid);
        self
    }

    /// Returns `true` when the socket satisfies all configured criteria.
    pub fn matches(&self, socket: &SocketInfo) -> bool {
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

        if let Some(pid) = self.owner_pid
            && !socket.is_owned_by_pid(pid)
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
