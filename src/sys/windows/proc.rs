use std::mem::size_of;
use std::mem::zeroed;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

pub fn get_process_name(pid: u32) -> Result<String, Box<dyn std::error::Error>> {
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok() }
        .ok_or("Failed to create snapshot")?;

    let mut process = unsafe { zeroed::<PROCESSENTRY32>() };
    process.dwSize = u32::try_from(size_of::<PROCESSENTRY32>())?;

    if unsafe { Process32First(h, &mut process) }.is_ok() {
        loop {
            if unsafe { Process32Next(h, &mut process) }.is_ok() {
                let id: u32 = process.th32ProcessID;
                if id == pid {
                    break;
                }
            } else {
                return Err("Failed to get process name".into());
            }
        }
    }

    unsafe {
        match CloseHandle(h).ok() {
            Some(_) => (),
            None => return Err("Failed to close handle".into()),
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
