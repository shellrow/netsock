#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents a process in the system.
///
/// This struct provides basic information about a process, including its ID and name.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Process {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
}
