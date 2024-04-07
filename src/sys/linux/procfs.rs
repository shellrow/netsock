use std::collections::HashMap;
use std::fs::{read_dir, read_link};

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

pub fn build_inode_proc_map() -> HashMap<u32, Vec<Process>> {
    let pids = read_dir("/proc/")
        .expect("Can't read /proc/")
        .filter_map(|d| d.ok()?.file_name().to_str()?.parse::<u32>().ok());
    let mut pid_by_inode: HashMap<u32, Vec<Process>> = HashMap::new();
    for pid in pids {
        let name = get_process_name(pid);
        if let Result::Ok(fds) = read_dir(format!("/proc/{}/fd", pid)) {
            let inodes = fds.filter_map(|fd| {
                let fd_file_name = fd.ok()?.file_name();
                let fd_str = fd_file_name.to_str()?;
                let path_buf = read_link(format!("/proc/{}/fd/{}", pid, fd_str)).ok()?;
                let link_str = path_buf.to_str()?;
                if link_str.starts_with("socket:[") {
                    let inode_str = &link_str[8..link_str.len() - 1];
                    inode_str.parse::<u32>().ok()
                } else {
                    Option::None
                }
            });
            for inode in inodes {
                pid_by_inode
                    .entry(inode)
                    .and_modify(|v: &mut Vec<Process>| {
                        v.push(Process {
                            pid: pid,
                            name: name.clone(),
                        })
                    })
                    .or_insert_with(|| {
                        vec![Process {
                            pid: pid,
                            name: name.clone(),
                        }]
                    });
            }
        }
    }
    pid_by_inode
}
