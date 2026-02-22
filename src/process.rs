#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Basic process metadata associated with a socket.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Process {
    /// Process identifier.
    pub pid: u32,
    /// Process name as reported by the operating system.
    pub name: String,
}
