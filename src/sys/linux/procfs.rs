use std::collections::HashMap;
use std::fs::{read_dir, read_link};
use std::sync::Arc;
use log::warn;

use crate::error::Error;
use crate::process::Process;

pub fn get_process_name(pid: u32) -> String {
    let path_buf = match read_link(format!("/proc/{}/exe", pid)) {
        Ok(path_buf) => path_buf,
        Err(_) => {
            return String::new();
        }
    };
    match path_buf.file_name() {
        Some(os_str) => os_str.to_string_lossy().to_string(),
        None => String::new(),
    }
}

pub fn build_inode_proc_map() -> Result<HashMap<u32, Vec<Process>>, Error> {
    let entries = read_dir("/proc/").map_err(Error::FailedToListProcesses)?;
    let mut pid_by_inode: HashMap<u32, Vec<Process>> = HashMap::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn!("Failed to read /proc entry: {err}");
                continue;
            }
        };

        let pid = match entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => continue,
        };

        let name = get_process_name(pid);

        let fd_entries = match read_dir(entry.path().join("fd")) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("Failed to read file descriptors for pid {pid}: {err}");
                continue;
            }
        };

        for fd in fd_entries {
            let fd = match fd {
                Ok(fd) => fd,
                Err(err) => {
                    warn!("Failed to inspect descriptor for pid {pid}: {err}");
                    continue;
                }
            };

            let link_path = match read_link(fd.path()) {
                Ok(path) => path,
                Err(err) => {
                    warn!("Failed to read descriptor link for pid {pid}: {err}");
                    continue;
                }
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
                pid_by_inode
                    .entry(inode)
                    .or_insert_with(Vec::new)
                    .push(Process {
                        pid,
                        name: name.clone(),
                    });
            }
        }
    }

    Ok(pid_by_inode)
}

#[derive(Clone, Default)]
pub struct ProcessCache {
    inner: Arc<HashMap<u32, Arc<[Process]>>>,
}

impl ProcessCache {
    pub fn snapshot() -> Result<Self, Error> {
        let map = build_inode_proc_map()?;
        Ok(Self::from_map(map))
    }

    pub fn refresh(&mut self) -> Result<(), Error> {
        *self = Self::snapshot()?;
        Ok(())
    }

    pub fn clone_processes(&self, inode: u32) -> Vec<Process> {
        self.inner
            .get(&inode)
            .map(|processes| processes.as_ref().to_vec())
            .unwrap_or_default()
    }

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
