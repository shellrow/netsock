use crate::state::TcpState;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSING,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
};

impl From<u32> for TcpState {
    fn from(tcp_state: u32) -> TcpState {
        match tcp_state as i32 {
            MIB_TCP_STATE_CLOSED => TcpState::Closed,
            MIB_TCP_STATE_LISTEN => TcpState::Listen,
            MIB_TCP_STATE_SYN_SENT => TcpState::SynSent,
            MIB_TCP_STATE_SYN_RCVD => TcpState::SynReceived,
            MIB_TCP_STATE_ESTAB => TcpState::Established,
            MIB_TCP_STATE_FIN_WAIT1 => TcpState::FinWait1,
            MIB_TCP_STATE_FIN_WAIT2 => TcpState::FinWait2,
            MIB_TCP_STATE_CLOSE_WAIT => TcpState::CloseWait,
            MIB_TCP_STATE_CLOSING => TcpState::Closing,
            MIB_TCP_STATE_LAST_ACK => TcpState::LastAck,
            MIB_TCP_STATE_TIME_WAIT => TcpState::TimeWait,
            MIB_TCP_STATE_DELETE_TCB => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
}
