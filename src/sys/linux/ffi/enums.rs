#![allow(non_camel_case_types)]

#[allow(unused_imports)]
use crate::sys::linux::ffi::types::*;
use libc::*;

pub const SOCK_DIAG_BY_FAMILY: __u16 = 20;
pub type INET_DIAG_TYPE = c_int;
pub const INET_DIAG_INFO: INET_DIAG_TYPE = 2;
