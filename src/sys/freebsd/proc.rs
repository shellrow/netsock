use std::os::raw::c_int;

use crate::error::Error;

pub fn get_process_name(pid: c_int) -> Result<String, Error> {
    // On FreeBSD, we read the process name from /proc/<pid>/cmdline
    // or use ki_comm from kinfo_proc
    let path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = std::fs::read_to_string(&path) {
        if let Some(name) = cmdline.split('\0').next() {
            if !name.is_empty() {
                // Get just the executable name, not the full path
                return Ok(name
                    .split('/')
                    .last()
                    .unwrap_or(name)
                    .to_string());
            }
        }
    }
    
    // Fallback to a generic name
    Ok(format!("process_{}", pid))
}
