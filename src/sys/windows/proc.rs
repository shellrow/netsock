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
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

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

    let mut process = unsafe { zeroed::<PROCESSENTRY32W>() };
    process.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>())
        .map_err(|err| Error::FailedToListProcesses(io::Error::other(err)))?;

    unsafe {
        if Process32FirstW(h, &mut process) == FALSE {
            return Err(Error::FailedToListProcesses(io::Error::last_os_error()));
        }
    }

    let mut processes = HashMap::new();
    loop {
        let name = &process.szExeFile;
        let len = name
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(name.len());
        processes.insert(
            process.th32ProcessID,
            String::from_utf16_lossy(&name[..len]),
        );

        unsafe {
            if Process32NextW(h, &mut process) == FALSE {
                let error = io::Error::last_os_error();
                if error.raw_os_error()
                    != Some(windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES as i32)
                {
                    return Err(Error::FailedToListProcesses(error));
                }
                break;
            }
        }
    }

    Ok(processes)
}
