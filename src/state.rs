use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// TCP connection state reported by the operating system.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
        f.write_str(match self {
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
            TcpState::Unknown => "UNKNOWN",
        })
    }
}

impl From<&str> for TcpState {
    fn from(tcp_state: &str) -> TcpState {
        match tcp_state {
            "CLOSED" => TcpState::Closed,
            "LISTEN" => TcpState::Listen,
            "SYN_SENT" => TcpState::SynSent,
            "SYN_RCVD" => TcpState::SynReceived,
            "ESTABLISHED" => TcpState::Established,
            "FIN_WAIT_1" => TcpState::FinWait1,
            "FIN_WAIT_2" => TcpState::FinWait2,
            "CLOSE_WAIT" => TcpState::CloseWait,
            "CLOSING" => TcpState::Closing,
            "LAST_ACK" => TcpState::LastAck,
            "TIME_WAIT" => TcpState::TimeWait,
            "DELETE_TCB" => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
}
