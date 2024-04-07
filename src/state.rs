use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents the various states of a TCP connection.
///
/// Each state in this enumeration corresponds to a specific phase in the lifecycle of a TCP
/// connection, detailing the protocol's behavior at each stage. These states are crucial for
/// understanding and managing TCP connections within network programming.
///
/// # Variants
/// - `Closed`: The connection is not active and not waiting for any incoming messages.
/// - `Listen`: The server is listening for incoming connection requests.
/// - `SynSent`: A SYN message has been sent, and the connection is awaiting a matching SYN-ACK.
/// - `SynReceived`: A SYN message has been received, and a SYN-ACK has been sent in response, awaiting ACK.
/// - `Established`: The TCP connection is established, and data can be transmitted.
/// - `FinWait1`: The connection is closed on one side, and it is waiting for a FIN-ACK.
/// - `FinWait2`: The first FIN has been acknowledged, and the connection is waiting for a terminal FIN.
/// - `CloseWait`: The connection is waiting for a close request from the local user.
/// - `Closing`: Both sides have initiated a connection termination.
/// - `LastAck`: Waiting for the last ACK in response to a FIN message.
/// - `TimeWait`: Waiting for a period of time to ensure the remote TCP received the acknowledgment of its connection termination request.
/// - `DeleteTcb`: Waiting to delete the TCP control block after sending a connection termination request.
/// - `Unknown`: The state of the TCP connection is unknown or not applicable.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TcpState::Closed => "CLOSED",
                TcpState::Listen => "LISTEN",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RCVD",
                TcpState::Established => "ESTABLISHED",
                TcpState::FinWait1 => "FIN_WAIT_1",
                TcpState::FinWait2 => "FIN_WAIT_2",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::Closing => "CLOSING",
                TcpState::LastAck => "LAST_ACK",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::DeleteTcb => "DELETE_TCB",
                TcpState::Unknown => "__UNKNOWN",
            }
        )
    }
}
