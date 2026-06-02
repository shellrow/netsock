use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::mem::zeroed;

use crate::error::Error;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
};

fn process_entry_name(process: &PROCESSENTRY32) -> Result<String, Error> {
    let name = process.szExeFile;
    let len = name
        .iter()
        .position(|&x| x == 0)
        .ok_or_else(|| Error::FailedToListProcesses(io::Error::other("invalid process name")))?;
    String::from_utf8(name[0..len].iter().map(|e| *e as u8).collect()).map_err(|err| {
        Error::FailedToListProcesses(io::Error::new(io::ErrorKind::InvalidData, err))
    })
}

pub fn get_process_names() -> Result<HashMap<u32, String>, Error> {
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h == INVALID_HANDLE_VALUE {
        return Err(Error::FailedToListProcesses(io::Error::last_os_error()));
    }
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _guard = HandleGuard(h);

    let mut process = unsafe { zeroed::<PROCESSENTRY32>() };
    process.dwSize = u32::try_from(size_of::<PROCESSENTRY32>())
        .map_err(|err| Error::FailedToListProcesses(io::Error::other(err)))?;

    unsafe {
        if Process32First(h, &mut process) == FALSE {
            return Err(Error::FailedToListProcesses(io::Error::last_os_error()));
        }
    }

    let mut processes = HashMap::new();
    loop {
        if let Ok(name) = process_entry_name(&process) {
            processes.insert(process.th32ProcessID, name);
        }

        unsafe {
            if Process32Next(h, &mut process) == FALSE {
                break;
            }
        }
    }

    Ok(processes)
}
