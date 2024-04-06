use std::ffi::{c_int, c_void};

use crate::sys::macos::ffi::libproc::proc_name;
pub const PROC_PID_PATH_INFO_MAXSIZE: usize = 4096;

/// Retrieves the name of a process by its process ID (PID).
///
/// This function queries the operating system for the name associated with a given PID. It
/// allocates a buffer to store the process name, then calls a low-level function to fill the buffer.
/// The process name is then converted to a Rust `String`.
///
/// # Parameters
/// - `pid`: The process ID (`c_int`) for which the process name is being retrieved.
///
/// # Returns
/// A `Result` which is either:
/// - `Ok(String)`: The name of the process as a `String` if the operation is successful.
/// - `Err(Box<dyn std::error::Error>)`: An error boxed as a dynamic error if the operation fails.
///
/// # Errors
/// - Returns an error if the `proc_name` function call returns a non-positive value, indicating
///   a failure to retrieve the process name.
/// - Returns an error if the process name contains an invalid UTF-8 sequence.
///
/// # Safety
/// This function uses unsafe blocks to interact with low-level system resources. It directly
/// manipulates memory allocated for the process name buffer, and it's crucial that this
/// operation is done correctly to avoid undefined behavior.
///
/// # Examples
/// ```
/// let pid = 1234;
/// match get_process_name(pid) {
///     Ok(name) => println!("Process name: {}", name),
///     Err(e) => eprintln!("Failed to get process name: {}", e),
/// }
/// ```
pub fn get_process_name(pid: c_int) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::with_capacity(PROC_PID_PATH_INFO_MAXSIZE);
    let buffer_ptr = buf.as_mut_ptr().cast::<c_void>();
    let buffer_size = u32::try_from(buf.capacity())?;

    let ret;
    unsafe {
        ret = proc_name(pid, buffer_ptr, buffer_size);
    };

    if ret <= 0 {
        return Err("Failed to get process name".into());
    }

    unsafe {
        buf.set_len(usize::try_from(ret)?);
    }

    match String::from_utf8(buf) {
        Ok(name) => Ok(name),
        Err(_) => Err("Invalid UTF sequence for process name".into()),
    }
}
