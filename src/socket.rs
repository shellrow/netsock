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
}
