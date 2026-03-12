//! FFI bindings for FreeBSD's libprocstat

#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

pub const KERN_PROC_PROC: c_int = 8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct procstat {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kinfo_proc {
    pub ki_structsize: c_int,
    pub ki_layout: c_int,
    pub ki_args: *mut c_void,
    pub ki_paddr: *mut c_void,
    pub ki_addr: *mut c_void,
    pub ki_tracep: *mut c_void,
    pub ki_textvp: *mut c_void,
    pub ki_fd: *mut c_void,
    pub ki_vmspace: *mut c_void,
    pub ki_wchan: *const c_void,
    pub ki_pid: i32,
    pub ki_ppid: i32,
    pub ki_pgid: i32,
    pub ki_tpgid: i32,
    pub ki_sid: i32,
    pub ki_tsid: i32,
    pub ki_jobc: c_int,
    pub ki_tdev: u64,
    pub ki_siglist: [u32; 4],
    pub ki_sigmask: [u32; 4],
    pub ki_sigignore: [u32; 4],
    pub ki_sigcatch: [u32; 4],
    pub ki_uid: u32,
    pub ki_ruid: u32,
    pub ki_svuid: u32,
    pub ki_rgid: u32,
    pub ki_svgid: u32,
    pub ki_ngroups: c_int,
    pub ki_groups: [u32; 16],
    pub ki_size: u64,
    pub ki_rssize: i64,
    pub ki_swrss: i64,
    pub ki_tsize: i64,
    pub ki_dsize: i64,
    pub ki_ssize: i64,
    pub ki_xstat: u16,
    pub ki_acflag: u16,
    pub ki_pctcpu: u32,
    pub ki_estcpu: u32,
    pub ki_slptime: u32,
    pub ki_swtime: u32,
    pub ki_cow: u32,
    pub ki_runtime: u64,
    pub ki_start: [i64; 2],
    pub ki_childtime: [i64; 2],
    pub ki_flag: i64,
    pub ki_kiflag: i64,
    pub ki_traceflag: c_int,
    pub ki_stat: c_char,
    pub ki_nice: c_char,
    pub ki_lock: c_char,
    pub ki_rqindex: c_char,
    pub ki_oncpu_old: c_char,
    pub ki_lastcpu_old: c_char,
    pub ki_tdname: [c_char; 20],
    pub ki_wmesg: [c_char; 9],
    pub ki_login: [c_char; 18],
    pub ki_lockname: [c_char; 9],
    pub ki_comm: [c_char; 20],
    pub ki_emul: [c_char; 17],
    pub ki_loginclass: [c_char; 18],
    pub ki_moretdname: [c_char; 4],
    pub ki_sparestrings: [[c_char; 23]; 2],
    pub ki_spareints: [c_int; 2],
    pub ki_oncpu: c_int,
    pub ki_lastcpu: c_int,
    pub ki_tracer: c_int,
    pub ki_flag2: c_int,
    pub ki_fibnum: c_int,
    pub ki_cr_flags: u32,
    pub ki_jid: c_int,
    pub ki_numthreads: c_int,
    pub ki_tid: i32,
    pub ki_pri: [u8; 36],
    pub ki_rusage: [u8; 144],
    pub ki_rusage_ch: [u8; 144],
    pub ki_pcb: *mut c_void,
    pub ki_kstack: *mut c_void,
    pub ki_udata: *mut c_void,
    pub ki_tdaddr: *mut c_void,
    pub ki_spareptrs: [*mut c_void; 6],
    pub ki_sparelongs: [i64; 12],
    pub ki_sflag: i64,
    pub ki_tdflags: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct filestat {
    pub fs_type: c_int,
    pub fs_flags: c_int,
    pub fs_fflags: c_int,
    pub fs_uflags: c_int,
    pub fs_fd: c_int,
    pub fs_ref_count: c_int,
    pub fs_offset: i64,
    pub fs_typedep: *mut c_void,
    pub fs_path: *mut c_char,
    pub next: filestat_next,
    pub fs_cap_rights: [u64; 2],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct filestat_next {
    pub stqe_next: *mut filestat,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct filestat_list {
    pub stqh_first: *mut filestat,
    pub stqh_last: *mut *mut filestat,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_storage {
    pub ss_len: u8,
    pub ss_family: u8,
    pub __ss_pad1: [u8; 6],
    pub __ss_align: i64,
    pub __ss_pad2: [u8; 112],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockstat {
    pub so_addr: u64,
    pub so_pcb: u64,
    pub unp_conn: u64,
    pub dom_family: c_int,
    pub proto: c_int,
    pub so_rcv_sb_state: c_int,
    pub so_snd_sb_state: c_int,
    pub sa_local: sockaddr_storage,
    pub sa_peer: sockaddr_storage,
    pub sock_type: c_int,
    pub dname: [c_char; 32],
    pub sendq: c_uint,
    pub recvq: c_uint,
}

pub const PS_FST_TYPE_SOCKET: c_int = 3;

unsafe extern "C" {
    pub fn procstat_open_sysctl() -> *mut procstat;
    pub fn procstat_close(procstat: *mut procstat);
    pub fn procstat_getprocs(
        procstat: *mut procstat,
        what: c_int,
        arg: c_int,
        count: *mut c_uint,
    ) -> *mut kinfo_proc;
    pub fn procstat_freeprocs(procstat: *mut procstat, p: *mut kinfo_proc);
    pub fn procstat_getfiles(
        procstat: *mut procstat,
        kp: *mut kinfo_proc,
        mmapped: c_int,
    ) -> *mut filestat_list;
    pub fn procstat_freefiles(procstat: *mut procstat, head: *mut filestat_list);
    pub fn procstat_get_socket_info(
        procstat: *mut procstat,
        fst: *mut filestat,
        sock: *mut sockstat,
        errbuf: *mut c_char,
    ) -> c_int;
}
