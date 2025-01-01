use crate::sys::linux::ffi::types::*;
use libc::*;

/*
 * From "linux/rtnetlink.h"
 */

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}

/*
 * From "linux/inet_diag.h"
 */

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct inet_diag_sockid {
    pub sport: __be16,
    pub dport: __be16,
    pub src: [__be32; 4],
    pub dst: [__be32; 4],
    pub if_: __u32,
    pub cookie: [__u32; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct inet_diag_msg {
    pub family: __u8,
    pub state: __u8,
    pub timer: __u8,
    pub retrans: __u8,
    pub id: inet_diag_sockid,
    pub expires: __u32,
    pub rqueue: __u32,
    pub wqueue: __u32,
    pub uid: __u32,
    pub inode: __u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct inet_diag_req {
    pub family: __u8, /* Family of addresses. */
    pub src_len: __u8,
    pub dst_len: __u8,
    pub ext: __u8, /* Query extended information */
    pub id: inet_diag_sockid,
    pub states: __u32, /* States to dump */
    pub dbs: __u32,    /* Tables to dump (NI) */
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct inet_diag_req_v2 {
    pub family: __u8,
    pub protocol: __u8,
    pub ext: __u8,
    pub pad: __u8,
    pub states: __u32,
    pub id: inet_diag_sockid,
}
