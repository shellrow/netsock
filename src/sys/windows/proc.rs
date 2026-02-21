use std::mem::size_of;
use std::mem::zeroed;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
};

pub fn get_process_name(pid: u32) -> Result<String, Box<dyn std::error::Error>> {
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h == INVALID_HANDLE_VALUE {
        return Err("Failed to create snapshot".into());
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
    process.dwSize = u32::try_from(size_of::<PROCESSENTRY32>())?;

    unsafe {
        if Process32First(h, &mut process) == FALSE {
            return Err("Failed to get first process".into());
        }
    }

    if process.th32ProcessID != pid {
        loop {
            unsafe {
                if Process32Next(h, &mut process) == FALSE {
                    return Err("Failed to get process name".into());
                }
            }
            if process.th32ProcessID == pid {
                break;
            }
        }
    }

    let name = process.szExeFile;
    let len = name
        .iter()
        .position(|&x| x == 0)
        .ok_or("Invalid process name")?;
    match String::from_utf8(name[0..len].iter().map(|e| *e as u8).collect()) {
        Ok(name) => Ok(name),
        Err(_) => Err("Invalid UTF sequence for process name".into()),
    }
}
