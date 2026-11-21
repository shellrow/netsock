use std::collections::HashMap;
use std::fs::{read_dir, read_link};
use std::sync::Arc;

use crate::error::Error;
use crate::process::Process;

fn get_process_name(pid: u32) -> String {
    read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default()
}

fn build_inode_proc_map() -> Result<HashMap<u32, Vec<Process>>, Error> {
    let entries = read_dir("/proc/").map_err(Error::FailedToListProcesses)?;
    let mut pid_by_inode: HashMap<u32, Vec<Process>> = HashMap::new();
    for entry in entries.flatten() {
        let pid = match entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => continue,
        };

        let mut process_name: Option<String> = None;

        let fd_entries = match read_dir(entry.path().join("fd")) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for fd in fd_entries.flatten() {
            let link_path = match read_link(fd.path()) {
                Ok(path) => path,
                Err(_) => continue,
            };

            let link_str = match link_path.to_str() {
                Some(link) => link,
                None => continue,
            };

            if let Some(inode) = link_str
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u32>().ok())
            {
                let owners = pid_by_inode.entry(inode).or_default();
                // All descriptors for this PID are visited together.
                if owners.last().is_some_and(|owner| owner.pid == pid) {
                    continue;
                }
                let name = process_name.get_or_insert_with(|| get_process_name(pid));
                owners.push(Process {
                    pid,
                    name: name.clone(),
                });
            }
        }
    }

    Ok(pid_by_inode)
}

/// Snapshot of the visible process owners indexed by socket inode. Clones share storage.
#[derive(Clone, Default)]
pub struct ProcessCache {
    inner: Arc<HashMap<u32, Arc<[Process]>>>,
}

impl ProcessCache {
    /// Scans the accessible process descriptors in `/proc`.
    pub fn snapshot() -> Result<Self, Error> {
        let map = build_inode_proc_map()?;
        Ok(Self::from_map(map))
    }

    /// Replaces this snapshot after a successful scan. Existing clones keep their data.
    pub fn refresh(&mut self) -> Result<(), Error> {
        *self = Self::snapshot()?;
        Ok(())
    }

    /// Copies the visible owners of an inode, or returns an empty vector.
    pub fn clone_processes(&self, inode: u32) -> Vec<Process> {
        self.inner
            .get(&inode)
            .map(|processes| processes.as_ref().to_vec())
            .unwrap_or_default()
    }

    /// Returns shared ownership data for an inode present in this snapshot.
    pub fn processes(&self, inode: u32) -> Option<Arc<[Process]>> {
        self.inner.get(&inode).cloned()
    }

    fn from_map(map: HashMap<u32, Vec<Process>>) -> Self {
        let converted = map
            .into_iter()
            .map(|(inode, processes)| (inode, Arc::<[Process]>::from(processes)))
            .collect();
        Self {
            inner: Arc::new(converted),
        }
    }
}
