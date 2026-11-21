use std::io;
use thiserror::Error;

/// Errors encountered while enumerating sockets and their owners.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A socket table could not be retrieved or decoded.
    #[error("failed to read socket table: {0}")]
    OsError(#[from] io::Error),

    /// The operating system could not enumerate processes.
    #[error("failed to list processes: {0}")]
    FailedToListProcesses(#[source] io::Error),

    /// The operating system could not enumerate a process's file descriptors.
    #[error("failed to query file descriptors: {0}")]
    FailedToQueryFileDescriptors(#[source] io::Error),
}
