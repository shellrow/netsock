use crate::error::Error;
use crate::process::Process;
use crate::state::TcpState;
use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents general information about a socket, encompassing both protocol-specific details
/// and process associations.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SocketInfo {
    /// Holds protocol-specific information, either TCP or UDP.
    pub protocol_socket_info: ProtocolSocketInfo,
    /// Lists processes associated with the socket, providing a connection between the socket
    /// and the processes utilizing it.
    pub processes: Vec<Process>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Represents the inode number of the socket on Linux or Android systems, offering a unique
    /// identifier in the filesystem's context.
    pub inode: u32,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    /// Stores the owner's user ID (UID) for this socket, indicating who has the rights to manipulate it.
    pub uid: u32,
}

/// Defines protocol-specific socket information, distinguishing between TCP and UDP protocols.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtocolSocketInfo {
    /// Contains TCP-specific information, encapsulating the state and local/remote endpoints.
    Tcp(TcpSocketInfo),
    /// Contains UDP-specific information, focusing on the local endpoint as UDP is connectionless.
    Udp(UdpSocketInfo),
}

/// Provides detailed information specific to TCP sockets, including endpoint addresses and the connection state.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpSocketInfo {
    /// The local IP address of the TCP socket.
    pub local_addr: IpAddr,
    /// The local port number of the TCP socket.
    pub local_port: u16,
    /// The remote IP address this socket is connected to.
    pub remote_addr: IpAddr,
    /// The remote port number this socket is connected to.
    pub remote_port: u16,
    /// The current state of the TCP connection.
    pub state: TcpState,
}

/// Provides information specific to UDP sockets, which primarily includes the local endpoint data.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UdpSocketInfo {
    /// The local IP address of the UDP socket.
    pub local_addr: IpAddr,
    /// The local port number of the UDP socket.
    pub local_port: u16,
}

impl SocketInfo {
    /// Retrieves the local IP address associated with this socket, applicable to both TCP and UDP.
    pub fn local_addr(&self) -> IpAddr {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => s.local_addr,
            ProtocolSocketInfo::Udp(s) => s.local_addr,
        }
    }

    /// Retrieves the local port associated with this socket, applicable to both TCP and UDP.
    pub fn local_port(&self) -> u16 {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => s.local_port,
            ProtocolSocketInfo::Udp(s) => s.local_port,
        }
    }

    /// Retrieves the remote IP address associated with the socket when applicable.
    pub fn remote_addr(&self) -> Option<IpAddr> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => Some(s.remote_addr),
            ProtocolSocketInfo::Udp(_) => None,
        }
    }

    /// Retrieves the remote port associated with the socket when applicable.
    pub fn remote_port(&self) -> Option<u16> {
        match &self.protocol_socket_info {
            ProtocolSocketInfo::Tcp(s) => Some(s.remote_port),
            ProtocolSocketInfo::Udp(_) => None,
        }
    }

    /// Returns true if any associated process matches the provided PID.
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

    /// Returns true if the socket satisfies the query criteria.
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        if let Some(addr) = self.local_addr {
            if socket.local_addr() != addr {
                return false;
            }
        }

        if let Some(port) = self.local_port {
            if socket.local_port() != port {
                return false;
            }
        }

        if let Some(addr) = self.remote_addr {
            if socket.remote_addr() != Some(addr) {
                return false;
            }
        }

        if let Some(port) = self.remote_port {
            if socket.remote_port() != Some(port) {
                return false;
            }
        }

        if let Some(pid) = self.owner_pid {
            if !socket.is_owned_by_pid(pid) {
                return false;
            }
        }

        true
    }
}

/// Provides convenient filtering helpers for iterators that yield [`SocketInfo`] values.
pub trait SocketIteratorExt: Iterator<Item = Result<SocketInfo, Error>> + Sized {
    /// Filters sockets using the provided [`SocketQuery`].
    fn filter_by_query(self, query: SocketQuery) -> FilterByQuery<Self> {
        FilterByQuery { inner: self, query }
    }
}

impl<I> SocketIteratorExt for I where I: Iterator<Item = Result<SocketInfo, Error>> + Sized {}

/// Iterator returned by [`SocketIteratorExt::filter_by_query`].
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
        while let Some(item) = self.inner.next() {
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
