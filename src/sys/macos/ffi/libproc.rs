#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused)]
#![allow(clippy::all)]

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage, Align> {
    storage: Storage,
    align: [Align; 0],
}
impl<Storage, Align> __BindgenBitfieldUnit<Storage, Align> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage, align: [] }
    }
}
impl<Storage, Align> __BindgenBitfieldUnit<Storage, Align>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub const __DARWIN_ONLY_64_BIT_INO_T: u32 = 0;
pub const __DARWIN_ONLY_VERS_1050: u32 = 0;
pub const __DARWIN_ONLY_UNIX_CONFORMANCE: u32 = 1;
pub const __DARWIN_UNIX03: u32 = 1;
pub const __DARWIN_64_BIT_INO_T: u32 = 1;
pub const __DARWIN_VERS_1050: u32 = 1;
pub const __DARWIN_NON_CANCELABLE: u32 = 0;
pub const __DARWIN_SUF_64_BIT_INO_T: &'static [u8; 9usize] = b"$INODE64\0";
pub const __DARWIN_SUF_1050: &'static [u8; 6usize] = b"$1050\0";
pub const __DARWIN_SUF_EXTSN: &'static [u8; 14usize] = b"$DARWIN_EXTSN\0";
pub const __DARWIN_C_ANSI: u32 = 4096;
pub const __DARWIN_C_FULL: u32 = 900000;
pub const __DARWIN_C_LEVEL: u32 = 900000;
pub const __STDC_WANT_LIB_EXT1__: u32 = 1;
pub const __DARWIN_NO_LONG_LONG: u32 = 0;
pub const _DARWIN_FEATURE_64_BIT_INODE: u32 = 1;
pub const _DARWIN_FEATURE_ONLY_UNIX_CONFORMANCE: u32 = 1;
pub const _DARWIN_FEATURE_UNIX_CONFORMANCE: u32 = 3;
pub const BSD: u32 = 199506;
pub const BSD4_3: u32 = 1;
pub const BSD4_4: u32 = 1;
pub const NeXTBSD: u32 = 1995064;
pub const NeXTBSD4_0: u32 = 0;
pub const __PTHREAD_SIZE__: u32 = 8176;
pub const __PTHREAD_ATTR_SIZE__: u32 = 56;
pub const __PTHREAD_MUTEXATTR_SIZE__: u32 = 8;
pub const __PTHREAD_MUTEX_SIZE__: u32 = 56;
pub const __PTHREAD_CONDATTR_SIZE__: u32 = 8;
pub const __PTHREAD_COND_SIZE__: u32 = 40;
pub const __PTHREAD_ONCE_SIZE__: u32 = 8;
pub const __PTHREAD_RWLOCK_SIZE__: u32 = 192;
pub const __PTHREAD_RWLOCKATTR_SIZE__: u32 = 16;
pub const _QUAD_HIGHWORD: u32 = 1;
pub const _QUAD_LOWWORD: u32 = 0;
pub const __DARWIN_LITTLE_ENDIAN: u32 = 1234;
pub const __DARWIN_BIG_ENDIAN: u32 = 4321;
pub const __DARWIN_PDP_ENDIAN: u32 = 3412;
pub const __DARWIN_BYTE_ORDER: u32 = 1234;
pub const LITTLE_ENDIAN: u32 = 1234;
pub const BIG_ENDIAN: u32 = 4321;
pub const PDP_ENDIAN: u32 = 3412;
pub const BYTE_ORDER: u32 = 1234;
pub const __DARWIN_FD_SETSIZE: u32 = 1024;
pub const __DARWIN_NBBY: u32 = 8;
pub const NBBY: u32 = 8;
pub const FD_SETSIZE: u32 = 1024;
pub const ARG_MAX: u32 = 262144;
pub const CHILD_MAX: u32 = 266;
pub const GID_MAX: u32 = 2147483647;
pub const LINK_MAX: u32 = 32767;
pub const MAX_CANON: u32 = 1024;
pub const MAX_INPUT: u32 = 1024;
pub const NAME_MAX: u32 = 255;
pub const NGROUPS_MAX: u32 = 16;
pub const UID_MAX: u32 = 2147483647;
pub const OPEN_MAX: u32 = 10240;
pub const PATH_MAX: u32 = 1024;
pub const PIPE_BUF: u32 = 512;
pub const BC_BASE_MAX: u32 = 99;
pub const BC_DIM_MAX: u32 = 2048;
pub const BC_SCALE_MAX: u32 = 99;
pub const BC_STRING_MAX: u32 = 1000;
pub const CHARCLASS_NAME_MAX: u32 = 14;
pub const COLL_WEIGHTS_MAX: u32 = 2;
pub const EQUIV_CLASS_MAX: u32 = 2;
pub const EXPR_NEST_MAX: u32 = 32;
pub const LINE_MAX: u32 = 2048;
pub const RE_DUP_MAX: u32 = 255;
pub const NZERO: u32 = 20;
pub const MAXCOMLEN: u32 = 16;
pub const MAXINTERP: u32 = 64;
pub const MAXLOGNAME: u32 = 255;
pub const MAXUPRC: u32 = 266;
pub const NCARGS: u32 = 262144;
pub const NGROUPS: u32 = 16;
pub const NOFILE: u32 = 256;
pub const NOGROUP: u32 = 65535;
pub const MAXHOSTNAMELEN: u32 = 256;
pub const MAXDOMNAMELEN: u32 = 256;
pub const NBPG: u32 = 4096;
pub const PGOFSET: u32 = 4095;
pub const PGSHIFT: u32 = 12;
pub const DEV_BSIZE: u32 = 512;
pub const DEV_BSHIFT: u32 = 9;
pub const BLKDEV_IOSIZE: u32 = 2048;
pub const MAXPHYS: u32 = 131072;
pub const CLSIZE: u32 = 1;
pub const CLSIZELOG2: u32 = 0;
pub const MSIZESHIFT: u32 = 8;
pub const MSIZE: u32 = 256;
pub const MCLSHIFT: u32 = 11;
pub const MCLBYTES: u32 = 2048;
pub const MBIGCLSHIFT: u32 = 12;
pub const MBIGCLBYTES: u32 = 4096;
pub const M16KCLSHIFT: u32 = 14;
pub const M16KCLBYTES: u32 = 16384;
pub const MCLOFSET: u32 = 2047;
pub const NMBCLUSTERS: u32 = 512;
pub const __DARWIN_CLK_TCK: u32 = 100;
pub const CHAR_BIT: u32 = 8;
pub const MB_LEN_MAX: u32 = 6;
pub const CLK_TCK: u32 = 100;
pub const SCHAR_MAX: u32 = 127;
pub const SCHAR_MIN: i32 = -128;
pub const UCHAR_MAX: u32 = 255;
pub const CHAR_MAX: u32 = 127;
pub const CHAR_MIN: i32 = -128;
pub const USHRT_MAX: u32 = 65535;
pub const SHRT_MAX: u32 = 32767;
pub const SHRT_MIN: i32 = -32768;
pub const UINT_MAX: u32 = 4294967295;
pub const INT_MAX: u32 = 2147483647;
pub const INT_MIN: i32 = -2147483648;
pub const ULONG_MAX: i32 = -1;
pub const LONG_MAX: u64 = 9223372036854775807;
pub const LONG_MIN: i64 = -9223372036854775808;
pub const ULLONG_MAX: i32 = -1;
pub const LLONG_MAX: u64 = 9223372036854775807;
pub const LLONG_MIN: i64 = -9223372036854775808;
pub const LONG_BIT: u32 = 64;
pub const SSIZE_MAX: u64 = 9223372036854775807;
pub const WORD_BIT: u32 = 32;
pub const SIZE_T_MAX: i32 = -1;
pub const UQUAD_MAX: i32 = -1;
pub const QUAD_MAX: u64 = 9223372036854775807;
pub const QUAD_MIN: i64 = -9223372036854775808;
pub const _POSIX_ARG_MAX: u32 = 4096;
pub const _POSIX_CHILD_MAX: u32 = 25;
pub const _POSIX_LINK_MAX: u32 = 8;
pub const _POSIX_MAX_CANON: u32 = 255;
pub const _POSIX_MAX_INPUT: u32 = 255;
pub const _POSIX_NAME_MAX: u32 = 14;
pub const _POSIX_NGROUPS_MAX: u32 = 8;
pub const _POSIX_OPEN_MAX: u32 = 20;
pub const _POSIX_PATH_MAX: u32 = 256;
pub const _POSIX_PIPE_BUF: u32 = 512;
pub const _POSIX_SSIZE_MAX: u32 = 32767;
pub const _POSIX_STREAM_MAX: u32 = 8;
pub const _POSIX_TZNAME_MAX: u32 = 6;
pub const _POSIX2_BC_BASE_MAX: u32 = 99;
pub const _POSIX2_BC_DIM_MAX: u32 = 2048;
pub const _POSIX2_BC_SCALE_MAX: u32 = 99;
pub const _POSIX2_BC_STRING_MAX: u32 = 1000;
pub const _POSIX2_EQUIV_CLASS_MAX: u32 = 2;
pub const _POSIX2_EXPR_NEST_MAX: u32 = 32;
pub const _POSIX2_LINE_MAX: u32 = 2048;
pub const _POSIX2_RE_DUP_MAX: u32 = 255;
pub const _POSIX_AIO_LISTIO_MAX: u32 = 2;
pub const _POSIX_AIO_MAX: u32 = 1;
pub const _POSIX_DELAYTIMER_MAX: u32 = 32;
pub const _POSIX_MQ_OPEN_MAX: u32 = 8;
pub const _POSIX_MQ_PRIO_MAX: u32 = 32;
pub const _POSIX_RTSIG_MAX: u32 = 8;
pub const _POSIX_SEM_NSEMS_MAX: u32 = 256;
pub const _POSIX_SEM_VALUE_MAX: u32 = 32767;
pub const _POSIX_SIGQUEUE_MAX: u32 = 32;
pub const _POSIX_TIMER_MAX: u32 = 32;
pub const _POSIX_CLOCKRES_MIN: u32 = 20000000;
pub const _POSIX_THREAD_DESTRUCTOR_ITERATIONS: u32 = 4;
pub const _POSIX_THREAD_KEYS_MAX: u32 = 128;
pub const _POSIX_THREAD_THREADS_MAX: u32 = 64;
pub const PTHREAD_DESTRUCTOR_ITERATIONS: u32 = 4;
pub const PTHREAD_KEYS_MAX: u32 = 512;
pub const PTHREAD_STACK_MIN: u32 = 8192;
pub const _POSIX_HOST_NAME_MAX: u32 = 255;
pub const _POSIX_LOGIN_NAME_MAX: u32 = 9;
pub const _POSIX_SS_REPL_MAX: u32 = 4;
pub const _POSIX_SYMLINK_MAX: u32 = 255;
pub const _POSIX_SYMLOOP_MAX: u32 = 8;
pub const _POSIX_TRACE_EVENT_NAME_MAX: u32 = 30;
pub const _POSIX_TRACE_NAME_MAX: u32 = 8;
pub const _POSIX_TRACE_SYS_MAX: u32 = 8;
pub const _POSIX_TRACE_USER_EVENT_MAX: u32 = 32;
pub const _POSIX_TTY_NAME_MAX: u32 = 9;
pub const _POSIX2_CHARCLASS_NAME_MAX: u32 = 14;
pub const _POSIX2_COLL_WEIGHTS_MAX: u32 = 2;
pub const _POSIX_RE_DUP_MAX: u32 = 255;
pub const OFF_MIN: i64 = -9223372036854775808;
pub const OFF_MAX: u64 = 9223372036854775807;
pub const PASS_MAX: u32 = 128;
pub const NL_ARGMAX: u32 = 9;
pub const NL_LANGMAX: u32 = 14;
pub const NL_MSGMAX: u32 = 32767;
pub const NL_NMAX: u32 = 1;
pub const NL_SETMAX: u32 = 255;
pub const NL_TEXTMAX: u32 = 2048;
pub const _XOPEN_IOV_MAX: u32 = 16;
pub const IOV_MAX: u32 = 1024;
pub const _XOPEN_NAME_MAX: u32 = 255;
pub const _XOPEN_PATH_MAX: u32 = 1024;
pub const __MAC_10_0: u32 = 1000;
pub const __MAC_10_1: u32 = 1010;
pub const __MAC_10_2: u32 = 1020;
pub const __MAC_10_3: u32 = 1030;
pub const __MAC_10_4: u32 = 1040;
pub const __MAC_10_5: u32 = 1050;
pub const __MAC_10_6: u32 = 1060;
pub const __MAC_10_7: u32 = 1070;
pub const __MAC_10_8: u32 = 1080;
pub const __MAC_10_9: u32 = 1090;
pub const __MAC_10_10: u32 = 101000;
pub const __MAC_10_10_2: u32 = 101002;
pub const __MAC_10_10_3: u32 = 101003;
pub const __MAC_10_11: u32 = 101100;
pub const __MAC_10_11_2: u32 = 101102;
pub const __MAC_10_11_3: u32 = 101103;
pub const __MAC_10_11_4: u32 = 101104;
pub const __MAC_10_12: u32 = 101200;
pub const __MAC_10_12_1: u32 = 101201;
pub const __MAC_10_12_2: u32 = 101202;
pub const __MAC_10_12_4: u32 = 101204;
pub const __MAC_10_13: u32 = 101300;
pub const __MAC_10_13_1: u32 = 101301;
pub const __MAC_10_13_2: u32 = 101302;
pub const __MAC_10_13_4: u32 = 101304;
pub const __IPHONE_2_0: u32 = 20000;
pub const __IPHONE_2_1: u32 = 20100;
pub const __IPHONE_2_2: u32 = 20200;
pub const __IPHONE_3_0: u32 = 30000;
pub const __IPHONE_3_1: u32 = 30100;
pub const __IPHONE_3_2: u32 = 30200;
pub const __IPHONE_4_0: u32 = 40000;
pub const __IPHONE_4_1: u32 = 40100;
pub const __IPHONE_4_2: u32 = 40200;
pub const __IPHONE_4_3: u32 = 40300;
pub const __IPHONE_5_0: u32 = 50000;
pub const __IPHONE_5_1: u32 = 50100;
pub const __IPHONE_6_0: u32 = 60000;
pub const __IPHONE_6_1: u32 = 60100;
pub const __IPHONE_7_0: u32 = 70000;
pub const __IPHONE_7_1: u32 = 70100;
pub const __IPHONE_8_0: u32 = 80000;
pub const __IPHONE_8_1: u32 = 80100;
pub const __IPHONE_8_2: u32 = 80200;
pub const __IPHONE_8_3: u32 = 80300;
pub const __IPHONE_8_4: u32 = 80400;
pub const __IPHONE_9_0: u32 = 90000;
pub const __IPHONE_9_1: u32 = 90100;
pub const __IPHONE_9_2: u32 = 90200;
pub const __IPHONE_9_3: u32 = 90300;
pub const __IPHONE_10_0: u32 = 100000;
pub const __IPHONE_10_1: u32 = 100100;
pub const __IPHONE_10_2: u32 = 100200;
pub const __IPHONE_10_3: u32 = 100300;
pub const __IPHONE_11_0: u32 = 110000;
pub const __IPHONE_11_1: u32 = 110100;
pub const __IPHONE_11_2: u32 = 110200;
pub const __IPHONE_11_3: u32 = 110300;
pub const __TVOS_9_0: u32 = 90000;
pub const __TVOS_9_1: u32 = 90100;
pub const __TVOS_9_2: u32 = 90200;
pub const __TVOS_10_0: u32 = 100000;
pub const __TVOS_10_0_1: u32 = 100001;
pub const __TVOS_10_1: u32 = 100100;
pub const __TVOS_10_2: u32 = 100200;
pub const __TVOS_11_0: u32 = 110000;
pub const __TVOS_11_1: u32 = 110100;
pub const __TVOS_11_2: u32 = 110200;
pub const __TVOS_11_3: u32 = 110300;
pub const __WATCHOS_1_0: u32 = 10000;
pub const __WATCHOS_2_0: u32 = 20000;
pub const __WATCHOS_2_1: u32 = 20100;
pub const __WATCHOS_2_2: u32 = 20200;
pub const __WATCHOS_3_0: u32 = 30000;
pub const __WATCHOS_3_1: u32 = 30100;
pub const __WATCHOS_3_1_1: u32 = 30101;
pub const __WATCHOS_3_2: u32 = 30200;
pub const __WATCHOS_4_0: u32 = 40000;
pub const __WATCHOS_4_1: u32 = 40100;
pub const __WATCHOS_4_2: u32 = 40200;
pub const __WATCHOS_4_3: u32 = 40300;
pub const __MAC_OS_X_VERSION_MAX_ALLOWED: u32 = 101304;
pub const __DARWIN_NSIG: u32 = 32;
pub const NSIG: u32 = 32;
pub const _I386_SIGNAL_H_: u32 = 1;
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGIOT: u32 = 6;
pub const SIGEMT: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGBUS: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGSYS: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGURG: u32 = 16;
pub const SIGSTOP: u32 = 17;
pub const SIGTSTP: u32 = 18;
pub const SIGCONT: u32 = 19;
pub const SIGCHLD: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGIO: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGINFO: u32 = 29;
pub const SIGUSR1: u32 = 30;
pub const SIGUSR2: u32 = 31;
pub const FP_PREC_24B: u32 = 0;
pub const FP_PREC_53B: u32 = 2;
pub const FP_PREC_64B: u32 = 3;
pub const FP_RND_NEAR: u32 = 0;
pub const FP_RND_DOWN: u32 = 1;
pub const FP_RND_UP: u32 = 2;
pub const FP_CHOP: u32 = 3;
pub const FP_STATE_BYTES: u32 = 512;
pub const SIGEV_NONE: u32 = 0;
pub const SIGEV_SIGNAL: u32 = 1;
pub const SIGEV_THREAD: u32 = 3;
pub const ILL_NOOP: u32 = 0;
pub const ILL_ILLOPC: u32 = 1;
pub const ILL_ILLTRP: u32 = 2;
pub const ILL_PRVOPC: u32 = 3;
pub const ILL_ILLOPN: u32 = 4;
pub const ILL_ILLADR: u32 = 5;
pub const ILL_PRVREG: u32 = 6;
pub const ILL_COPROC: u32 = 7;
pub const ILL_BADSTK: u32 = 8;
pub const FPE_NOOP: u32 = 0;
pub const FPE_FLTDIV: u32 = 1;
pub const FPE_FLTOVF: u32 = 2;
pub const FPE_FLTUND: u32 = 3;
pub const FPE_FLTRES: u32 = 4;
pub const FPE_FLTINV: u32 = 5;
pub const FPE_FLTSUB: u32 = 6;
pub const FPE_INTDIV: u32 = 7;
pub const FPE_INTOVF: u32 = 8;
pub const SEGV_NOOP: u32 = 0;
pub const SEGV_MAPERR: u32 = 1;
pub const SEGV_ACCERR: u32 = 2;
pub const BUS_NOOP: u32 = 0;
pub const BUS_ADRALN: u32 = 1;
pub const BUS_ADRERR: u32 = 2;
pub const BUS_OBJERR: u32 = 3;
pub const TRAP_BRKPT: u32 = 1;
pub const TRAP_TRACE: u32 = 2;
pub const CLD_NOOP: u32 = 0;
pub const CLD_EXITED: u32 = 1;
pub const CLD_KILLED: u32 = 2;
pub const CLD_DUMPED: u32 = 3;
pub const CLD_TRAPPED: u32 = 4;
pub const CLD_STOPPED: u32 = 5;
pub const CLD_CONTINUED: u32 = 6;
pub const POLL_IN: u32 = 1;
pub const POLL_OUT: u32 = 2;
pub const POLL_MSG: u32 = 3;
pub const POLL_ERR: u32 = 4;
pub const POLL_PRI: u32 = 5;
pub const POLL_HUP: u32 = 6;
pub const SA_ONSTACK: u32 = 1;
pub const SA_RESTART: u32 = 2;
pub const SA_RESETHAND: u32 = 4;
pub const SA_NOCLDSTOP: u32 = 8;
pub const SA_NODEFER: u32 = 16;
pub const SA_NOCLDWAIT: u32 = 32;
pub const SA_SIGINFO: u32 = 64;
pub const SA_USERTRAMP: u32 = 256;
pub const SA_64REGSET: u32 = 512;
pub const SA_USERSPACE_MASK: u32 = 127;
pub const SIG_BLOCK: u32 = 1;
pub const SIG_UNBLOCK: u32 = 2;
pub const SIG_SETMASK: u32 = 3;
pub const SI_USER: u32 = 65537;
pub const SI_QUEUE: u32 = 65538;
pub const SI_TIMER: u32 = 65539;
pub const SI_ASYNCIO: u32 = 65540;
pub const SI_MESGQ: u32 = 65541;
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 4;
pub const MINSIGSTKSZ: u32 = 32768;
pub const SIGSTKSZ: u32 = 131072;
pub const SV_ONSTACK: u32 = 1;
pub const SV_INTERRUPT: u32 = 2;
pub const SV_RESETHAND: u32 = 4;
pub const SV_NODEFER: u32 = 16;
pub const SV_NOCLDSTOP: u32 = 8;
pub const SV_SIGINFO: u32 = 64;
pub const PSWP: u32 = 0;
pub const PVM: u32 = 4;
pub const PINOD: u32 = 8;
pub const PRIBIO: u32 = 16;
pub const PVFS: u32 = 20;
pub const PZERO: u32 = 22;
pub const PSOCK: u32 = 24;
pub const PWAIT: u32 = 32;
pub const PLOCK: u32 = 36;
pub const PPAUSE: u32 = 40;
pub const PUSER: u32 = 50;
pub const MAXPRI: u32 = 127;
pub const PRIMASK: u32 = 255;
pub const PCATCH: u32 = 256;
pub const PTTYBLOCK: u32 = 512;
pub const PDROP: u32 = 1024;
pub const PSPIN: u32 = 2048;
pub const CMASK: u32 = 18;
pub const CLBYTES: u32 = 4096;
pub const CLOFSET: u32 = 4095;
pub const CLOFF: u32 = 4095;
pub const CLSHIFT: u32 = 12;
pub const CBLOCK: u32 = 64;
pub const CBQSIZE: u32 = 8;
pub const CROUND: u32 = 63;
pub const MAXBSIZE: u32 = 1048576;
pub const MAXPHYSIO: u32 = 131072;
pub const MAXFRAG: u32 = 8;
pub const MAXPHYSIO_WIRED: u32 = 16777216;
pub const MAXPATHLEN: u32 = 1024;
pub const MAXSYMLINKS: u32 = 32;
pub const MINBUCKET: u32 = 4;
pub const MAXALLOCSAVE: u32 = 8192;
pub const FSHIFT: u32 = 11;
pub const FSCALE: u32 = 2048;
pub const S_IFMT: u32 = 61440;
pub const S_IFIFO: u32 = 4096;
pub const S_IFCHR: u32 = 8192;
pub const S_IFDIR: u32 = 16384;
pub const S_IFBLK: u32 = 24576;
pub const S_IFREG: u32 = 32768;
pub const S_IFLNK: u32 = 40960;
pub const S_IFSOCK: u32 = 49152;
pub const S_IFWHT: u32 = 57344;
pub const S_IRWXU: u32 = 448;
pub const S_IRUSR: u32 = 256;
pub const S_IWUSR: u32 = 128;
pub const S_IXUSR: u32 = 64;
pub const S_IRWXG: u32 = 56;
pub const S_IRGRP: u32 = 32;
pub const S_IWGRP: u32 = 16;
pub const S_IXGRP: u32 = 8;
pub const S_IRWXO: u32 = 7;
pub const S_IROTH: u32 = 4;
pub const S_IWOTH: u32 = 2;
pub const S_IXOTH: u32 = 1;
pub const S_ISUID: u32 = 2048;
pub const S_ISGID: u32 = 1024;
pub const S_ISVTX: u32 = 512;
pub const S_ISTXT: u32 = 512;
pub const S_IREAD: u32 = 256;
pub const S_IWRITE: u32 = 128;
pub const S_IEXEC: u32 = 64;
pub const ACCESSPERMS: u32 = 511;
pub const ALLPERMS: u32 = 4095;
pub const DEFFILEMODE: u32 = 438;
pub const S_BLKSIZE: u32 = 512;
pub const UF_SETTABLE: u32 = 65535;
pub const UF_NODUMP: u32 = 1;
pub const UF_IMMUTABLE: u32 = 2;
pub const UF_APPEND: u32 = 4;
pub const UF_OPAQUE: u32 = 8;
pub const UF_COMPRESSED: u32 = 32;
pub const UF_TRACKED: u32 = 64;
pub const UF_DATAVAULT: u32 = 128;
pub const UF_HIDDEN: u32 = 32768;
pub const SF_SUPPORTED: u32 = 2031616;
pub const SF_SETTABLE: u32 = 4294901760;
pub const SF_ARCHIVED: u32 = 65536;
pub const SF_IMMUTABLE: u32 = 131072;
pub const SF_APPEND: u32 = 262144;
pub const SF_RESTRICTED: u32 = 524288;
pub const SF_NOUNLINK: u32 = 1048576;
pub const UTIME_NOW: i32 = -1;
pub const UTIME_OMIT: i32 = -2;
pub const AUDIT_RECORD_MAGIC: u32 = 2190085915;
pub const MAX_AUDIT_RECORDS: u32 = 20;
pub const MAXAUDITDATA: u32 = 32767;
pub const MAX_AUDIT_RECORD_SIZE: u32 = 32767;
pub const MIN_AUDIT_FILE_SIZE: u32 = 524288;
pub const AUDIT_HARD_LIMIT_FREE_BLOCKS: u32 = 4;
pub const AUDIT_TRIGGER_MIN: u32 = 1;
pub const AUDIT_TRIGGER_LOW_SPACE: u32 = 1;
pub const AUDIT_TRIGGER_ROTATE_KERNEL: u32 = 2;
pub const AUDIT_TRIGGER_READ_FILE: u32 = 3;
pub const AUDIT_TRIGGER_CLOSE_AND_DIE: u32 = 4;
pub const AUDIT_TRIGGER_NO_SPACE: u32 = 5;
pub const AUDIT_TRIGGER_ROTATE_USER: u32 = 6;
pub const AUDIT_TRIGGER_INITIALIZE: u32 = 7;
pub const AUDIT_TRIGGER_EXPIRE_TRAILS: u32 = 8;
pub const AUDIT_TRIGGER_MAX: u32 = 8;
pub const AUDITDEV_FILENAME: &'static [u8; 6usize] = b"audit\0";
pub const AUDIT_TRIGGER_FILE: &'static [u8; 11usize] = b"/dev/audit\0";
pub const AU_DEFAUDITSID: u32 = 0;
pub const AU_ASSIGN_ASID: i32 = -1;
pub const AUC_UNSET: u32 = 0;
pub const AUC_AUDITING: u32 = 1;
pub const AUC_NOAUDIT: u32 = 2;
pub const AUC_DISABLED: i32 = -1;
pub const A_OLDGETPOLICY: u32 = 2;
pub const A_OLDSETPOLICY: u32 = 3;
pub const A_GETKMASK: u32 = 4;
pub const A_SETKMASK: u32 = 5;
pub const A_OLDGETQCTRL: u32 = 6;
pub const A_OLDSETQCTRL: u32 = 7;
pub const A_GETCWD: u32 = 8;
pub const A_GETCAR: u32 = 9;
pub const A_GETSTAT: u32 = 12;
pub const A_SETSTAT: u32 = 13;
pub const A_SETUMASK: u32 = 14;
pub const A_SETSMASK: u32 = 15;
pub const A_OLDGETCOND: u32 = 20;
pub const A_OLDSETCOND: u32 = 21;
pub const A_GETCLASS: u32 = 22;
pub const A_SETCLASS: u32 = 23;
pub const A_GETPINFO: u32 = 24;
pub const A_SETPMASK: u32 = 25;
pub const A_SETFSIZE: u32 = 26;
pub const A_GETFSIZE: u32 = 27;
pub const A_GETPINFO_ADDR: u32 = 28;
pub const A_GETKAUDIT: u32 = 29;
pub const A_SETKAUDIT: u32 = 30;
pub const A_SENDTRIGGER: u32 = 31;
pub const A_GETSINFO_ADDR: u32 = 32;
pub const A_GETPOLICY: u32 = 33;
pub const A_SETPOLICY: u32 = 34;
pub const A_GETQCTRL: u32 = 35;
pub const A_SETQCTRL: u32 = 36;
pub const A_GETCOND: u32 = 37;
pub const A_SETCOND: u32 = 38;
pub const A_GETSFLAGS: u32 = 39;
pub const A_SETSFLAGS: u32 = 40;
pub const AUDIT_CNT: u32 = 1;
pub const AUDIT_AHLT: u32 = 2;
pub const AUDIT_ARGV: u32 = 4;
pub const AUDIT_ARGE: u32 = 8;
pub const AUDIT_SEQ: u32 = 16;
pub const AUDIT_WINDATA: u32 = 32;
pub const AUDIT_USER: u32 = 64;
pub const AUDIT_GROUP: u32 = 128;
pub const AUDIT_TRAIL: u32 = 256;
pub const AUDIT_PATH: u32 = 512;
pub const AUDIT_SCNT: u32 = 1024;
pub const AUDIT_PUBLIC: u32 = 2048;
pub const AUDIT_ZONENAME: u32 = 4096;
pub const AUDIT_PERZONE: u32 = 8192;
pub const AQ_HIWATER: u32 = 100;
pub const AQ_MAXHIGH: u32 = 10000;
pub const AQ_LOWATER: u32 = 10;
pub const AQ_BUFSZ: u32 = 32767;
pub const AQ_MAXBUFSZ: u32 = 1048576;
pub const AU_FS_MINFREE: u32 = 20;
pub const AU_IPv4: u32 = 4;
pub const AU_IPv6: u32 = 16;
pub const __WORDSIZE: u32 = 64;
pub const INT8_MAX: u32 = 127;
pub const INT16_MAX: u32 = 32767;
pub const INT32_MAX: u32 = 2147483647;
pub const INT64_MAX: u64 = 9223372036854775807;
pub const INT8_MIN: i32 = -128;
pub const INT16_MIN: i32 = -32768;
pub const INT32_MIN: i32 = -2147483648;
pub const INT64_MIN: i64 = -9223372036854775808;
pub const UINT8_MAX: u32 = 255;
pub const UINT16_MAX: u32 = 65535;
pub const UINT32_MAX: u32 = 4294967295;
pub const UINT64_MAX: i32 = -1;
pub const INT_LEAST8_MIN: i32 = -128;
pub const INT_LEAST16_MIN: i32 = -32768;
pub const INT_LEAST32_MIN: i32 = -2147483648;
pub const INT_LEAST64_MIN: i64 = -9223372036854775808;
pub const INT_LEAST8_MAX: u32 = 127;
pub const INT_LEAST16_MAX: u32 = 32767;
pub const INT_LEAST32_MAX: u32 = 2147483647;
pub const INT_LEAST64_MAX: u64 = 9223372036854775807;
pub const UINT_LEAST8_MAX: u32 = 255;
pub const UINT_LEAST16_MAX: u32 = 65535;
pub const UINT_LEAST32_MAX: u32 = 4294967295;
pub const UINT_LEAST64_MAX: i32 = -1;
pub const INT_FAST8_MIN: i32 = -128;
pub const INT_FAST16_MIN: i32 = -32768;
pub const INT_FAST32_MIN: i32 = -2147483648;
pub const INT_FAST64_MIN: i64 = -9223372036854775808;
pub const INT_FAST8_MAX: u32 = 127;
pub const INT_FAST16_MAX: u32 = 32767;
pub const INT_FAST32_MAX: u32 = 2147483647;
pub const INT_FAST64_MAX: u64 = 9223372036854775807;
pub const UINT_FAST8_MAX: u32 = 255;
pub const UINT_FAST16_MAX: u32 = 65535;
pub const UINT_FAST32_MAX: u32 = 4294967295;
pub const UINT_FAST64_MAX: i32 = -1;
pub const INTPTR_MAX: u64 = 9223372036854775807;
pub const INTPTR_MIN: i64 = -9223372036854775808;
pub const UINTPTR_MAX: i32 = -1;
pub const INTMAX_MIN: i64 = -9223372036854775808;
pub const INTMAX_MAX: u64 = 9223372036854775807;
pub const UINTMAX_MAX: i32 = -1;
pub const PTRDIFF_MIN: i64 = -9223372036854775808;
pub const PTRDIFF_MAX: u64 = 9223372036854775807;
pub const SIZE_MAX: i32 = -1;
pub const RSIZE_MAX: i32 = -1;
pub const WINT_MIN: i32 = -2147483648;
pub const WINT_MAX: u32 = 2147483647;
pub const SIG_ATOMIC_MIN: i32 = -2147483648;
pub const SIG_ATOMIC_MAX: u32 = 2147483647;
pub const TRUE: u32 = 1;
pub const FALSE: u32 = 0;
pub const BYTE_SIZE: u32 = 8;
pub const I386_PGBYTES: u32 = 4096;
pub const I386_PGSHIFT: u32 = 12;
pub const PAGE_SIZE: u32 = 4096;
pub const PAGE_SHIFT: u32 = 12;
pub const PAGE_MASK: u32 = 4095;
pub const PAGE_MAX_SHIFT: u32 = 12;
pub const PAGE_MAX_SIZE: u32 = 4096;
pub const PAGE_MAX_MASK: u32 = 4095;
pub const PAGE_MIN_SHIFT: u32 = 12;
pub const PAGE_MIN_SIZE: u32 = 4096;
pub const PAGE_MIN_MASK: u32 = 4095;
pub const I386_LPGBYTES: u32 = 2097152;
pub const I386_LPGSHIFT: u32 = 21;
pub const I386_LPGMASK: u32 = 2097151;
pub const MACH_PORT_NULL: u32 = 0;
pub const MACH_PORT_TYPE_DNREQUEST: u32 = 2147483648;
pub const MACH_PORT_TYPE_SPREQUEST: u32 = 1073741824;
pub const MACH_PORT_TYPE_SPREQUEST_DELAYED: u32 = 536870912;
pub const MACH_PORT_SRIGHTS_NONE: u32 = 0;
pub const MACH_PORT_SRIGHTS_PRESENT: u32 = 1;
pub const MACH_PORT_QLIMIT_ZERO: u32 = 0;
pub const MACH_PORT_QLIMIT_BASIC: u32 = 5;
pub const MACH_PORT_QLIMIT_SMALL: u32 = 16;
pub const MACH_PORT_QLIMIT_LARGE: u32 = 1024;
pub const MACH_PORT_QLIMIT_KERNEL: u32 = 65534;
pub const MACH_PORT_QLIMIT_MIN: u32 = 0;
pub const MACH_PORT_QLIMIT_DEFAULT: u32 = 5;
pub const MACH_PORT_QLIMIT_MAX: u32 = 1024;
pub const MACH_PORT_STATUS_FLAG_TEMPOWNER: u32 = 1;
pub const MACH_PORT_STATUS_FLAG_GUARDED: u32 = 2;
pub const MACH_PORT_STATUS_FLAG_STRICT_GUARD: u32 = 4;
pub const MACH_PORT_STATUS_FLAG_IMP_DONATION: u32 = 8;
pub const MACH_PORT_STATUS_FLAG_REVIVE: u32 = 16;
pub const MACH_PORT_STATUS_FLAG_TASKPTR: u32 = 32;
pub const MACH_PORT_LIMITS_INFO: u32 = 1;
pub const MACH_PORT_RECEIVE_STATUS: u32 = 2;
pub const MACH_PORT_DNREQUESTS_SIZE: u32 = 3;
pub const MACH_PORT_TEMPOWNER: u32 = 4;
pub const MACH_PORT_IMPORTANCE_RECEIVER: u32 = 5;
pub const MACH_PORT_DENAP_RECEIVER: u32 = 6;
pub const MACH_PORT_INFO_EXT: u32 = 7;
pub const MACH_PORT_DNREQUESTS_SIZE_COUNT: u32 = 1;
pub const MPO_CONTEXT_AS_GUARD: u32 = 1;
pub const MPO_QLIMIT: u32 = 2;
pub const MPO_TEMPOWNER: u32 = 4;
pub const MPO_IMPORTANCE_RECEIVER: u32 = 8;
pub const MPO_INSERT_SEND_RIGHT: u32 = 16;
pub const MPO_STRICT: u32 = 32;
pub const MPO_DENAP_RECEIVER: u32 = 64;
pub const GUARD_TYPE_MACH_PORT: u32 = 1;
pub const CRF_NOMEMBERD: u32 = 1;
pub const CRF_MAC_ENFORCE: u32 = 2;
pub const XUCRED_VERSION: u32 = 0;
pub const ITIMER_REAL: u32 = 0;
pub const ITIMER_VIRTUAL: u32 = 1;
pub const ITIMER_PROF: u32 = 2;
pub const DST_NONE: u32 = 0;
pub const DST_USA: u32 = 1;
pub const DST_AUST: u32 = 2;
pub const DST_WET: u32 = 3;
pub const DST_MET: u32 = 4;
pub const DST_EET: u32 = 5;
pub const DST_CAN: u32 = 6;
pub const __DARWIN_WCHAR_MIN: i32 = -2147483648;
pub const _FORTIFY_SOURCE: u32 = 2;
pub const CLOCKS_PER_SEC: u32 = 1000000;
pub const FSOPT_NOFOLLOW: u32 = 1;
pub const FSOPT_NOINMEMUPDATE: u32 = 2;
pub const FSOPT_REPORT_FULLSIZE: u32 = 4;
pub const FSOPT_PACK_INVAL_ATTRS: u32 = 8;
pub const FSOPT_ATTR_CMN_EXTENDED: u32 = 32;
pub const SEARCHFS_MAX_SEARCHPARMS: u32 = 4096;
pub const ATTR_BIT_MAP_COUNT: u32 = 5;
pub const VOL_CAPABILITIES_FORMAT: u32 = 0;
pub const VOL_CAPABILITIES_INTERFACES: u32 = 1;
pub const VOL_CAPABILITIES_RESERVED1: u32 = 2;
pub const VOL_CAPABILITIES_RESERVED2: u32 = 3;
pub const ATTR_MAX_BUFFER: u32 = 8192;
pub const VOL_CAP_FMT_PERSISTENTOBJECTIDS: u32 = 1;
pub const VOL_CAP_FMT_SYMBOLICLINKS: u32 = 2;
pub const VOL_CAP_FMT_HARDLINKS: u32 = 4;
pub const VOL_CAP_FMT_JOURNAL: u32 = 8;
pub const VOL_CAP_FMT_JOURNAL_ACTIVE: u32 = 16;
pub const VOL_CAP_FMT_NO_ROOT_TIMES: u32 = 32;
pub const VOL_CAP_FMT_SPARSE_FILES: u32 = 64;
pub const VOL_CAP_FMT_ZERO_RUNS: u32 = 128;
pub const VOL_CAP_FMT_CASE_SENSITIVE: u32 = 256;
pub const VOL_CAP_FMT_CASE_PRESERVING: u32 = 512;
pub const VOL_CAP_FMT_FAST_STATFS: u32 = 1024;
pub const VOL_CAP_FMT_2TB_FILESIZE: u32 = 2048;
pub const VOL_CAP_FMT_OPENDENYMODES: u32 = 4096;
pub const VOL_CAP_FMT_HIDDEN_FILES: u32 = 8192;
pub const VOL_CAP_FMT_PATH_FROM_ID: u32 = 16384;
pub const VOL_CAP_FMT_NO_VOLUME_SIZES: u32 = 32768;
pub const VOL_CAP_FMT_DECMPFS_COMPRESSION: u32 = 65536;
pub const VOL_CAP_FMT_64BIT_OBJECT_IDS: u32 = 131072;
pub const VOL_CAP_FMT_DIR_HARDLINKS: u32 = 262144;
pub const VOL_CAP_FMT_DOCUMENT_ID: u32 = 524288;
pub const VOL_CAP_FMT_WRITE_GENERATION_COUNT: u32 = 1048576;
pub const VOL_CAP_FMT_NO_IMMUTABLE_FILES: u32 = 2097152;
pub const VOL_CAP_FMT_NO_PERMISSIONS: u32 = 4194304;
pub const VOL_CAP_INT_SEARCHFS: u32 = 1;
pub const VOL_CAP_INT_ATTRLIST: u32 = 2;
pub const VOL_CAP_INT_NFSEXPORT: u32 = 4;
pub const VOL_CAP_INT_READDIRATTR: u32 = 8;
pub const VOL_CAP_INT_EXCHANGEDATA: u32 = 16;
pub const VOL_CAP_INT_COPYFILE: u32 = 32;
pub const VOL_CAP_INT_ALLOCATE: u32 = 64;
pub const VOL_CAP_INT_VOL_RENAME: u32 = 128;
pub const VOL_CAP_INT_ADVLOCK: u32 = 256;
pub const VOL_CAP_INT_FLOCK: u32 = 512;
pub const VOL_CAP_INT_EXTENDED_SECURITY: u32 = 1024;
pub const VOL_CAP_INT_USERACCESS: u32 = 2048;
pub const VOL_CAP_INT_MANLOCK: u32 = 4096;
pub const VOL_CAP_INT_NAMEDSTREAMS: u32 = 8192;
pub const VOL_CAP_INT_EXTENDED_ATTR: u32 = 16384;
pub const VOL_CAP_INT_CLONE: u32 = 65536;
pub const VOL_CAP_INT_SNAPSHOT: u32 = 131072;
pub const VOL_CAP_INT_RENAME_SWAP: u32 = 262144;
pub const VOL_CAP_INT_RENAME_EXCL: u32 = 524288;
pub const ATTR_CMN_NAME: u32 = 1;
pub const ATTR_CMN_DEVID: u32 = 2;
pub const ATTR_CMN_FSID: u32 = 4;
pub const ATTR_CMN_OBJTYPE: u32 = 8;
pub const ATTR_CMN_OBJTAG: u32 = 16;
pub const ATTR_CMN_OBJID: u32 = 32;
pub const ATTR_CMN_OBJPERMANENTID: u32 = 64;
pub const ATTR_CMN_PAROBJID: u32 = 128;
pub const ATTR_CMN_SCRIPT: u32 = 256;
pub const ATTR_CMN_CRTIME: u32 = 512;
pub const ATTR_CMN_MODTIME: u32 = 1024;
pub const ATTR_CMN_CHGTIME: u32 = 2048;
pub const ATTR_CMN_ACCTIME: u32 = 4096;
pub const ATTR_CMN_BKUPTIME: u32 = 8192;
pub const ATTR_CMN_FNDRINFO: u32 = 16384;
pub const ATTR_CMN_OWNERID: u32 = 32768;
pub const ATTR_CMN_GRPID: u32 = 65536;
pub const ATTR_CMN_ACCESSMASK: u32 = 131072;
pub const ATTR_CMN_FLAGS: u32 = 262144;
pub const ATTR_CMN_GEN_COUNT: u32 = 524288;
pub const ATTR_CMN_DOCUMENT_ID: u32 = 1048576;
pub const ATTR_CMN_USERACCESS: u32 = 2097152;
pub const ATTR_CMN_EXTENDED_SECURITY: u32 = 4194304;
pub const ATTR_CMN_UUID: u32 = 8388608;
pub const ATTR_CMN_GRPUUID: u32 = 16777216;
pub const ATTR_CMN_FILEID: u32 = 33554432;
pub const ATTR_CMN_PARENTID: u32 = 67108864;
pub const ATTR_CMN_FULLPATH: u32 = 134217728;
pub const ATTR_CMN_ADDEDTIME: u32 = 268435456;
pub const ATTR_CMN_ERROR: u32 = 536870912;
pub const ATTR_CMN_DATA_PROTECT_FLAGS: u32 = 1073741824;
pub const ATTR_CMN_RETURNED_ATTRS: u32 = 2147483648;
pub const ATTR_CMN_VALIDMASK: u32 = 4294967295;
pub const ATTR_CMN_SETMASK: u32 = 1372061440;
pub const ATTR_CMN_VOLSETMASK: u32 = 26368;
pub const ATTR_VOL_FSTYPE: u32 = 1;
pub const ATTR_VOL_SIGNATURE: u32 = 2;
pub const ATTR_VOL_SIZE: u32 = 4;
pub const ATTR_VOL_SPACEFREE: u32 = 8;
pub const ATTR_VOL_SPACEAVAIL: u32 = 16;
pub const ATTR_VOL_MINALLOCATION: u32 = 32;
pub const ATTR_VOL_ALLOCATIONCLUMP: u32 = 64;
pub const ATTR_VOL_IOBLOCKSIZE: u32 = 128;
pub const ATTR_VOL_OBJCOUNT: u32 = 256;
pub const ATTR_VOL_FILECOUNT: u32 = 512;
pub const ATTR_VOL_DIRCOUNT: u32 = 1024;
pub const ATTR_VOL_MAXOBJCOUNT: u32 = 2048;
pub const ATTR_VOL_MOUNTPOINT: u32 = 4096;
pub const ATTR_VOL_NAME: u32 = 8192;
pub const ATTR_VOL_MOUNTFLAGS: u32 = 16384;
pub const ATTR_VOL_MOUNTEDDEVICE: u32 = 32768;
pub const ATTR_VOL_ENCODINGSUSED: u32 = 65536;
pub const ATTR_VOL_CAPABILITIES: u32 = 131072;
pub const ATTR_VOL_UUID: u32 = 262144;
pub const ATTR_VOL_QUOTA_SIZE: u32 = 268435456;
pub const ATTR_VOL_RESERVED_SIZE: u32 = 536870912;
pub const ATTR_VOL_ATTRIBUTES: u32 = 1073741824;
pub const ATTR_VOL_INFO: u32 = 2147483648;
pub const ATTR_VOL_VALIDMASK: u32 = 4027056127;
pub const ATTR_VOL_SETMASK: u32 = 2147491840;
pub const ATTR_DIR_LINKCOUNT: u32 = 1;
pub const ATTR_DIR_ENTRYCOUNT: u32 = 2;
pub const ATTR_DIR_MOUNTSTATUS: u32 = 4;
pub const ATTR_DIR_ALLOCSIZE: u32 = 8;
pub const ATTR_DIR_IOBLOCKSIZE: u32 = 16;
pub const ATTR_DIR_DATALENGTH: u32 = 32;
pub const DIR_MNTSTATUS_MNTPOINT: u32 = 1;
pub const DIR_MNTSTATUS_TRIGGER: u32 = 2;
pub const ATTR_DIR_VALIDMASK: u32 = 63;
pub const ATTR_DIR_SETMASK: u32 = 0;
pub const ATTR_FILE_LINKCOUNT: u32 = 1;
pub const ATTR_FILE_TOTALSIZE: u32 = 2;
pub const ATTR_FILE_ALLOCSIZE: u32 = 4;
pub const ATTR_FILE_IOBLOCKSIZE: u32 = 8;
pub const ATTR_FILE_DEVTYPE: u32 = 32;
pub const ATTR_FILE_FORKCOUNT: u32 = 128;
pub const ATTR_FILE_FORKLIST: u32 = 256;
pub const ATTR_FILE_DATALENGTH: u32 = 512;
pub const ATTR_FILE_DATAALLOCSIZE: u32 = 1024;
pub const ATTR_FILE_RSRCLENGTH: u32 = 4096;
pub const ATTR_FILE_RSRCALLOCSIZE: u32 = 8192;
pub const ATTR_FILE_VALIDMASK: u32 = 14335;
pub const ATTR_FILE_SETMASK: u32 = 32;
pub const ATTR_CMNEXT_RELPATH: u32 = 4;
pub const ATTR_CMNEXT_PRIVATESIZE: u32 = 8;
pub const ATTR_CMNEXT_LINKID: u32 = 16;
pub const ATTR_CMNEXT_VALIDMASK: u32 = 28;
pub const ATTR_CMNEXT_SETMASK: u32 = 0;
pub const ATTR_FORK_TOTALSIZE: u32 = 1;
pub const ATTR_FORK_ALLOCSIZE: u32 = 2;
pub const ATTR_FORK_RESERVED: u32 = 4294967295;
pub const ATTR_FORK_VALIDMASK: u32 = 3;
pub const ATTR_FORK_SETMASK: u32 = 0;
pub const ATTR_CMN_NAMEDATTRCOUNT: u32 = 524288;
pub const ATTR_CMN_NAMEDATTRLIST: u32 = 1048576;
pub const ATTR_FILE_CLUMPSIZE: u32 = 16;
pub const ATTR_FILE_FILETYPE: u32 = 64;
pub const ATTR_FILE_DATAEXTENTS: u32 = 2048;
pub const ATTR_FILE_RSRCEXTENTS: u32 = 16384;
pub const ATTR_BULK_REQUIRED: u32 = 2147483649;
pub const SRCHFS_START: u32 = 1;
pub const SRCHFS_MATCHPARTIALNAMES: u32 = 2;
pub const SRCHFS_MATCHDIRS: u32 = 4;
pub const SRCHFS_MATCHFILES: u32 = 8;
pub const SRCHFS_SKIPLINKS: u32 = 16;
pub const SRCHFS_SKIPINVISIBLE: u32 = 32;
pub const SRCHFS_SKIPPACKAGES: u32 = 64;
pub const SRCHFS_SKIPINAPPROPRIATE: u32 = 128;
pub const SRCHFS_NEGATEPARAMS: u32 = 2147483648;
pub const SRCHFS_VALIDOPTIONSMASK: u32 = 2147483903;
pub const FST_EOF: i32 = -1;
pub const MFSNAMELEN: u32 = 15;
pub const MFSTYPENAMELEN: u32 = 16;
pub const MNAMELEN: u32 = 1024;
pub const MNT_RDONLY: u32 = 1;
pub const MNT_SYNCHRONOUS: u32 = 2;
pub const MNT_NOEXEC: u32 = 4;
pub const MNT_NOSUID: u32 = 8;
pub const MNT_NODEV: u32 = 16;
pub const MNT_UNION: u32 = 32;
pub const MNT_ASYNC: u32 = 64;
pub const MNT_CPROTECT: u32 = 128;
pub const MNT_EXPORTED: u32 = 256;
pub const MNT_QUARANTINE: u32 = 1024;
pub const MNT_LOCAL: u32 = 4096;
pub const MNT_QUOTA: u32 = 8192;
pub const MNT_ROOTFS: u32 = 16384;
pub const MNT_DOVOLFS: u32 = 32768;
pub const MNT_DONTBROWSE: u32 = 1048576;
pub const MNT_IGNORE_OWNERSHIP: u32 = 2097152;
pub const MNT_AUTOMOUNTED: u32 = 4194304;
pub const MNT_JOURNALED: u32 = 8388608;
pub const MNT_NOUSERXATTR: u32 = 16777216;
pub const MNT_DEFWRITE: u32 = 33554432;
pub const MNT_MULTILABEL: u32 = 67108864;
pub const MNT_NOATIME: u32 = 268435456;
pub const MNT_SNAPSHOT: u32 = 1073741824;
pub const MNT_UNKNOWNPERMISSIONS: u32 = 2097152;
pub const MNT_VISFLAGMASK: u32 = 1475409407;
pub const MNT_UPDATE: u32 = 65536;
pub const MNT_NOBLOCK: u32 = 131072;
pub const MNT_RELOAD: u32 = 262144;
pub const MNT_FORCE: u32 = 524288;
pub const MNT_CMDFLAGS: u32 = 983040;
pub const VFS_GENERIC: u32 = 0;
pub const VFS_NUMMNTOPS: u32 = 1;
pub const VFS_MAXTYPENUM: u32 = 1;
pub const VFS_CONF: u32 = 2;
pub const MNT_WAIT: u32 = 1;
pub const MNT_NOWAIT: u32 = 2;
pub const MNT_DWAIT: u32 = 4;
pub const VFS_CTL_VERS1: u32 = 1;
pub const VFS_CTL_STATFS: u32 = 65537;
pub const VFS_CTL_UMOUNT: u32 = 65538;
pub const VFS_CTL_QUERY: u32 = 65539;
pub const VFS_CTL_NEWADDR: u32 = 65540;
pub const VFS_CTL_TIMEO: u32 = 65541;
pub const VFS_CTL_NOLOCKS: u32 = 65542;
pub const VFS_CTL_SADDR: u32 = 65543;
pub const VFS_CTL_DISC: u32 = 65544;
pub const VFS_CTL_SERVERINFO: u32 = 65545;
pub const VFS_CTL_NSTATUS: u32 = 65546;
pub const VQ_NOTRESP: u32 = 1;
pub const VQ_NEEDAUTH: u32 = 2;
pub const VQ_LOWDISK: u32 = 4;
pub const VQ_MOUNT: u32 = 8;
pub const VQ_UNMOUNT: u32 = 16;
pub const VQ_DEAD: u32 = 32;
pub const VQ_ASSIST: u32 = 64;
pub const VQ_NOTRESPLOCK: u32 = 128;
pub const VQ_UPDATE: u32 = 256;
pub const VQ_VERYLOWDISK: u32 = 512;
pub const VQ_SYNCEVENT: u32 = 1024;
pub const VQ_SERVEREVENT: u32 = 2048;
pub const VQ_QUOTA: u32 = 4096;
pub const VQ_NEARLOWDISK: u32 = 8192;
pub const VQ_DESIRED_DISK: u32 = 16384;
pub const VQ_FLAG8000: u32 = 32768;
pub const NFSV4_MAX_FH_SIZE: u32 = 128;
pub const NFSV3_MAX_FH_SIZE: u32 = 64;
pub const NFSV2_MAX_FH_SIZE: u32 = 32;
pub const PRIO_PROCESS: u32 = 0;
pub const PRIO_PGRP: u32 = 1;
pub const PRIO_USER: u32 = 2;
pub const PRIO_DARWIN_THREAD: u32 = 3;
pub const PRIO_DARWIN_PROCESS: u32 = 4;
pub const PRIO_MIN: i32 = -20;
pub const PRIO_MAX: u32 = 20;
pub const PRIO_DARWIN_BG: u32 = 4096;
pub const PRIO_DARWIN_NONUI: u32 = 4097;
pub const RUSAGE_SELF: u32 = 0;
pub const RUSAGE_CHILDREN: i32 = -1;
pub const RUSAGE_INFO_V0: u32 = 0;
pub const RUSAGE_INFO_V1: u32 = 1;
pub const RUSAGE_INFO_V2: u32 = 2;
pub const RUSAGE_INFO_V3: u32 = 3;
pub const RUSAGE_INFO_V4: u32 = 4;
pub const RUSAGE_INFO_CURRENT: u32 = 4;
pub const RLIMIT_CPU: u32 = 0;
pub const RLIMIT_FSIZE: u32 = 1;
pub const RLIMIT_DATA: u32 = 2;
pub const RLIMIT_STACK: u32 = 3;
pub const RLIMIT_CORE: u32 = 4;
pub const RLIMIT_AS: u32 = 5;
pub const RLIMIT_RSS: u32 = 5;
pub const RLIMIT_MEMLOCK: u32 = 6;
pub const RLIMIT_NPROC: u32 = 7;
pub const RLIMIT_NOFILE: u32 = 8;
pub const RLIM_NLIMITS: u32 = 9;
pub const _RLIMIT_POSIX_FLAG: u32 = 4096;
pub const RLIMIT_WAKEUPS_MONITOR: u32 = 1;
pub const RLIMIT_CPU_USAGE_MONITOR: u32 = 2;
pub const RLIMIT_THREAD_CPULIMITS: u32 = 3;
pub const WAKEMON_ENABLE: u32 = 1;
pub const WAKEMON_DISABLE: u32 = 2;
pub const WAKEMON_GET_PARAMS: u32 = 4;
pub const WAKEMON_SET_DEFAULTS: u32 = 8;
pub const WAKEMON_MAKE_FATAL: u32 = 16;
pub const CPUMON_MAKE_FATAL: u32 = 4096;
pub const IOPOL_TYPE_DISK: u32 = 0;
pub const IOPOL_SCOPE_PROCESS: u32 = 0;
pub const IOPOL_SCOPE_THREAD: u32 = 1;
pub const IOPOL_SCOPE_DARWIN_BG: u32 = 2;
pub const IOPOL_DEFAULT: u32 = 0;
pub const IOPOL_IMPORTANT: u32 = 1;
pub const IOPOL_PASSIVE: u32 = 2;
pub const IOPOL_THROTTLE: u32 = 3;
pub const IOPOL_UTILITY: u32 = 4;
pub const IOPOL_STANDARD: u32 = 5;
pub const IOPOL_APPLICATION: u32 = 5;
pub const IOPOL_NORMAL: u32 = 1;
pub const true_: u32 = 1;
pub const false_: u32 = 0;
pub const __bool_true_false_are_defined: u32 = 1;
pub const KEV_INET_SUBCLASS: u32 = 1;
pub const KEV_INET_NEW_ADDR: u32 = 1;
pub const KEV_INET_CHANGED_ADDR: u32 = 2;
pub const KEV_INET_ADDR_DELETED: u32 = 3;
pub const KEV_INET_SIFDSTADDR: u32 = 4;
pub const KEV_INET_SIFBRDADDR: u32 = 5;
pub const KEV_INET_SIFNETMASK: u32 = 6;
pub const KEV_INET_ARPCOLLISION: u32 = 7;
pub const KEV_INET_PORTINUSE: u32 = 8;
pub const KEV_INET_ARPRTRFAILURE: u32 = 9;
pub const KEV_INET_ARPRTRALIVE: u32 = 10;
pub const KEV_DL_SUBCLASS: u32 = 2;
pub const KEV_DL_SIFFLAGS: u32 = 1;
pub const KEV_DL_SIFMETRICS: u32 = 2;
pub const KEV_DL_SIFMTU: u32 = 3;
pub const KEV_DL_SIFPHYS: u32 = 4;
pub const KEV_DL_SIFMEDIA: u32 = 5;
pub const KEV_DL_SIFGENERIC: u32 = 6;
pub const KEV_DL_ADDMULTI: u32 = 7;
pub const KEV_DL_DELMULTI: u32 = 8;
pub const KEV_DL_IF_ATTACHED: u32 = 9;
pub const KEV_DL_IF_DETACHING: u32 = 10;
pub const KEV_DL_IF_DETACHED: u32 = 11;
pub const KEV_DL_LINK_OFF: u32 = 12;
pub const KEV_DL_LINK_ON: u32 = 13;
pub const KEV_DL_PROTO_ATTACHED: u32 = 14;
pub const KEV_DL_PROTO_DETACHED: u32 = 15;
pub const KEV_DL_LINK_ADDRESS_CHANGED: u32 = 16;
pub const KEV_DL_WAKEFLAGS_CHANGED: u32 = 17;
pub const KEV_DL_IF_IDLE_ROUTE_REFCNT: u32 = 18;
pub const KEV_DL_IFCAP_CHANGED: u32 = 19;
pub const KEV_DL_LINK_QUALITY_METRIC_CHANGED: u32 = 20;
pub const KEV_DL_NODE_PRESENCE: u32 = 21;
pub const KEV_DL_NODE_ABSENCE: u32 = 22;
pub const KEV_DL_MASTER_ELECTED: u32 = 23;
pub const KEV_DL_ISSUES: u32 = 24;
pub const KEV_DL_IFDELEGATE_CHANGED: u32 = 25;
pub const KEV_DL_AWDL_RESTRICTED: u32 = 26;
pub const KEV_DL_AWDL_UNRESTRICTED: u32 = 27;
pub const KEV_DL_RRC_STATE_CHANGED: u32 = 28;
pub const KEV_DL_QOS_MODE_CHANGED: u32 = 29;
pub const KEV_INET6_SUBCLASS: u32 = 6;
pub const KEV_INET6_NEW_USER_ADDR: u32 = 1;
pub const KEV_INET6_CHANGED_ADDR: u32 = 2;
pub const KEV_INET6_ADDR_DELETED: u32 = 3;
pub const KEV_INET6_NEW_LL_ADDR: u32 = 4;
pub const KEV_INET6_NEW_RTADV_ADDR: u32 = 5;
pub const KEV_INET6_DEFROUTER: u32 = 6;
pub const KEV_INET6_REQUEST_NAT64_PREFIX: u32 = 7;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_RDM: u32 = 4;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SO_DEBUG: u32 = 1;
pub const SO_ACCEPTCONN: u32 = 2;
pub const SO_REUSEADDR: u32 = 4;
pub const SO_KEEPALIVE: u32 = 8;
pub const SO_DONTROUTE: u32 = 16;
pub const SO_BROADCAST: u32 = 32;
pub const SO_USELOOPBACK: u32 = 64;
pub const SO_LINGER: u32 = 128;
pub const SO_OOBINLINE: u32 = 256;
pub const SO_REUSEPORT: u32 = 512;
pub const SO_TIMESTAMP: u32 = 1024;
pub const SO_TIMESTAMP_MONOTONIC: u32 = 2048;
pub const SO_DONTTRUNC: u32 = 8192;
pub const SO_WANTMORE: u32 = 16384;
pub const SO_WANTOOBFLAG: u32 = 32768;
pub const SO_SNDBUF: u32 = 4097;
pub const SO_RCVBUF: u32 = 4098;
pub const SO_SNDLOWAT: u32 = 4099;
pub const SO_RCVLOWAT: u32 = 4100;
pub const SO_SNDTIMEO: u32 = 4101;
pub const SO_RCVTIMEO: u32 = 4102;
pub const SO_ERROR: u32 = 4103;
pub const SO_TYPE: u32 = 4104;
pub const SO_LABEL: u32 = 4112;
pub const SO_PEERLABEL: u32 = 4113;
pub const SO_NREAD: u32 = 4128;
pub const SO_NKE: u32 = 4129;
pub const SO_NOSIGPIPE: u32 = 4130;
pub const SO_NOADDRERR: u32 = 4131;
pub const SO_NWRITE: u32 = 4132;
pub const SO_REUSESHAREUID: u32 = 4133;
pub const SO_NOTIFYCONFLICT: u32 = 4134;
pub const SO_UPCALLCLOSEWAIT: u32 = 4135;
pub const SO_LINGER_SEC: u32 = 4224;
pub const SO_RANDOMPORT: u32 = 4226;
pub const SO_NP_EXTENSIONS: u32 = 4227;
pub const SO_NUMRCVPKT: u32 = 4370;
pub const SO_NET_SERVICE_TYPE: u32 = 4374;
pub const NET_SERVICE_TYPE_BE: u32 = 0;
pub const NET_SERVICE_TYPE_BK: u32 = 1;
pub const NET_SERVICE_TYPE_SIG: u32 = 2;
pub const NET_SERVICE_TYPE_VI: u32 = 3;
pub const NET_SERVICE_TYPE_VO: u32 = 4;
pub const NET_SERVICE_TYPE_RV: u32 = 5;
pub const NET_SERVICE_TYPE_AV: u32 = 6;
pub const NET_SERVICE_TYPE_OAM: u32 = 7;
pub const NET_SERVICE_TYPE_RD: u32 = 8;
pub const SO_NETSVC_MARKING_LEVEL: u32 = 4377;
pub const NETSVC_MRKNG_UNKNOWN: u32 = 0;
pub const NETSVC_MRKNG_LVL_L2: u32 = 1;
pub const NETSVC_MRKNG_LVL_L3L2_ALL: u32 = 2;
pub const NETSVC_MRKNG_LVL_L3L2_BK: u32 = 3;
pub const SAE_ASSOCID_ANY: u32 = 0;
pub const SAE_CONNID_ANY: u32 = 0;
pub const CONNECT_RESUME_ON_READ_WRITE: u32 = 1;
pub const CONNECT_DATA_IDEMPOTENT: u32 = 2;
pub const CONNECT_DATA_AUTHENTICATED: u32 = 4;
pub const SONPX_SETOPTSHUT: u32 = 1;
pub const SOL_SOCKET: u32 = 65535;
pub const AF_UNSPEC: u32 = 0;
pub const AF_UNIX: u32 = 1;
pub const AF_LOCAL: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_IMPLINK: u32 = 3;
pub const AF_PUP: u32 = 4;
pub const AF_CHAOS: u32 = 5;
pub const AF_NS: u32 = 6;
pub const AF_ISO: u32 = 7;
pub const AF_OSI: u32 = 7;
pub const AF_ECMA: u32 = 8;
pub const AF_DATAKIT: u32 = 9;
pub const AF_CCITT: u32 = 10;
pub const AF_SNA: u32 = 11;
pub const AF_DECnet: u32 = 12;
pub const AF_DLI: u32 = 13;
pub const AF_LAT: u32 = 14;
pub const AF_HYLINK: u32 = 15;
pub const AF_APPLETALK: u32 = 16;
pub const AF_ROUTE: u32 = 17;
pub const AF_LINK: u32 = 18;
pub const pseudo_AF_XTP: u32 = 19;
pub const AF_COIP: u32 = 20;
pub const AF_CNT: u32 = 21;
pub const pseudo_AF_RTIP: u32 = 22;
pub const AF_IPX: u32 = 23;
pub const AF_SIP: u32 = 24;
pub const pseudo_AF_PIP: u32 = 25;
pub const AF_NDRV: u32 = 27;
pub const AF_ISDN: u32 = 28;
pub const AF_E164: u32 = 28;
pub const pseudo_AF_KEY: u32 = 29;
pub const AF_INET6: u32 = 30;
pub const AF_NATM: u32 = 31;
pub const AF_SYSTEM: u32 = 32;
pub const AF_NETBIOS: u32 = 33;
pub const AF_PPP: u32 = 34;
pub const pseudo_AF_HDRCMPLT: u32 = 35;
pub const AF_RESERVED_36: u32 = 36;
pub const AF_IEEE80211: u32 = 37;
pub const AF_UTUN: u32 = 38;
pub const AF_MAX: u32 = 40;
pub const SOCK_MAXADDRLEN: u32 = 255;
pub const _SS_MAXSIZE: u32 = 128;
pub const PF_UNSPEC: u32 = 0;
pub const PF_LOCAL: u32 = 1;
pub const PF_UNIX: u32 = 1;
pub const PF_INET: u32 = 2;
pub const PF_IMPLINK: u32 = 3;
pub const PF_PUP: u32 = 4;
pub const PF_CHAOS: u32 = 5;
pub const PF_NS: u32 = 6;
pub const PF_ISO: u32 = 7;
pub const PF_OSI: u32 = 7;
pub const PF_ECMA: u32 = 8;
pub const PF_DATAKIT: u32 = 9;
pub const PF_CCITT: u32 = 10;
pub const PF_SNA: u32 = 11;
pub const PF_DECnet: u32 = 12;
pub const PF_DLI: u32 = 13;
pub const PF_LAT: u32 = 14;
pub const PF_HYLINK: u32 = 15;
pub const PF_APPLETALK: u32 = 16;
pub const PF_ROUTE: u32 = 17;
pub const PF_LINK: u32 = 18;
pub const PF_XTP: u32 = 19;
pub const PF_COIP: u32 = 20;
pub const PF_CNT: u32 = 21;
pub const PF_SIP: u32 = 24;
pub const PF_IPX: u32 = 23;
pub const PF_RTIP: u32 = 22;
pub const PF_PIP: u32 = 25;
pub const PF_NDRV: u32 = 27;
pub const PF_ISDN: u32 = 28;
pub const PF_KEY: u32 = 29;
pub const PF_INET6: u32 = 30;
pub const PF_NATM: u32 = 31;
pub const PF_SYSTEM: u32 = 32;
pub const PF_NETBIOS: u32 = 33;
pub const PF_PPP: u32 = 34;
pub const PF_RESERVED_36: u32 = 36;
pub const PF_UTUN: u32 = 38;
pub const PF_MAX: u32 = 40;
pub const NET_MAXID: u32 = 40;
pub const NET_RT_DUMP: u32 = 1;
pub const NET_RT_FLAGS: u32 = 2;
pub const NET_RT_IFLIST: u32 = 3;
pub const NET_RT_STAT: u32 = 4;
pub const NET_RT_TRASH: u32 = 5;
pub const NET_RT_IFLIST2: u32 = 6;
pub const NET_RT_DUMP2: u32 = 7;
pub const NET_RT_MAXID: u32 = 10;
pub const SOMAXCONN: u32 = 128;
pub const MSG_OOB: u32 = 1;
pub const MSG_PEEK: u32 = 2;
pub const MSG_DONTROUTE: u32 = 4;
pub const MSG_EOR: u32 = 8;
pub const MSG_TRUNC: u32 = 16;
pub const MSG_CTRUNC: u32 = 32;
pub const MSG_WAITALL: u32 = 64;
pub const MSG_DONTWAIT: u32 = 128;
pub const MSG_EOF: u32 = 256;
pub const MSG_WAITSTREAM: u32 = 512;
pub const MSG_FLUSH: u32 = 1024;
pub const MSG_HOLD: u32 = 2048;
pub const MSG_SEND: u32 = 4096;
pub const MSG_HAVEMORE: u32 = 8192;
pub const MSG_RCVMORE: u32 = 16384;
pub const MSG_NEEDSA: u32 = 65536;
pub const SCM_RIGHTS: u32 = 1;
pub const SCM_TIMESTAMP: u32 = 2;
pub const SCM_CREDS: u32 = 3;
pub const SCM_TIMESTAMP_MONOTONIC: u32 = 4;
pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;
pub const SOL_LOCAL: u32 = 0;
pub const LOCAL_PEERCRED: u32 = 1;
pub const LOCAL_PEERPID: u32 = 2;
pub const LOCAL_PEEREPID: u32 = 3;
pub const LOCAL_PEERUUID: u32 = 4;
pub const LOCAL_PEEREUUID: u32 = 5;
pub const KEV_CTL_SUBCLASS: u32 = 2;
pub const KEV_CTL_REGISTERED: u32 = 1;
pub const KEV_CTL_DEREGISTERED: u32 = 2;
pub const MAX_KCTL_NAME: u32 = 96;
pub const EVFILT_READ: i32 = -1;
pub const EVFILT_WRITE: i32 = -2;
pub const EVFILT_AIO: i32 = -3;
pub const EVFILT_VNODE: i32 = -4;
pub const EVFILT_PROC: i32 = -5;
pub const EVFILT_SIGNAL: i32 = -6;
pub const EVFILT_TIMER: i32 = -7;
pub const EVFILT_MACHPORT: i32 = -8;
pub const EVFILT_FS: i32 = -9;
pub const EVFILT_USER: i32 = -10;
pub const EVFILT_VM: i32 = -12;
pub const EVFILT_EXCEPT: i32 = -15;
pub const EVFILT_SYSCOUNT: u32 = 17;
pub const EVFILT_THREADMARKER: u32 = 17;
pub const KEVENT_FLAG_NONE: u32 = 0;
pub const KEVENT_FLAG_IMMEDIATE: u32 = 1;
pub const KEVENT_FLAG_ERROR_EVENTS: u32 = 2;
pub const EV_ADD: u32 = 1;
pub const EV_DELETE: u32 = 2;
pub const EV_ENABLE: u32 = 4;
pub const EV_DISABLE: u32 = 8;
pub const EV_ONESHOT: u32 = 16;
pub const EV_CLEAR: u32 = 32;
pub const EV_RECEIPT: u32 = 64;
pub const EV_DISPATCH: u32 = 128;
pub const EV_UDATA_SPECIFIC: u32 = 256;
pub const EV_DISPATCH2: u32 = 384;
pub const EV_VANISHED: u32 = 512;
pub const EV_SYSFLAGS: u32 = 61440;
pub const EV_FLAG0: u32 = 4096;
pub const EV_FLAG1: u32 = 8192;
pub const EV_EOF: u32 = 32768;
pub const EV_ERROR: u32 = 16384;
pub const EV_POLL: u32 = 4096;
pub const EV_OOBAND: u32 = 8192;
pub const NOTE_TRIGGER: u32 = 16777216;
pub const NOTE_FFNOP: u32 = 0;
pub const NOTE_FFAND: u32 = 1073741824;
pub const NOTE_FFOR: u32 = 2147483648;
pub const NOTE_FFCOPY: u32 = 3221225472;
pub const NOTE_FFCTRLMASK: u32 = 3221225472;
pub const NOTE_FFLAGSMASK: u32 = 16777215;
pub const NOTE_LOWAT: u32 = 1;
pub const NOTE_OOB: u32 = 2;
pub const NOTE_DELETE: u32 = 1;
pub const NOTE_WRITE: u32 = 2;
pub const NOTE_EXTEND: u32 = 4;
pub const NOTE_ATTRIB: u32 = 8;
pub const NOTE_LINK: u32 = 16;
pub const NOTE_RENAME: u32 = 32;
pub const NOTE_REVOKE: u32 = 64;
pub const NOTE_NONE: u32 = 128;
pub const NOTE_FUNLOCK: u32 = 256;
pub const NOTE_EXIT: u32 = 2147483648;
pub const NOTE_FORK: u32 = 1073741824;
pub const NOTE_EXEC: u32 = 536870912;
pub const NOTE_SIGNAL: u32 = 134217728;
pub const NOTE_EXITSTATUS: u32 = 67108864;
pub const NOTE_EXIT_DETAIL: u32 = 33554432;
pub const NOTE_PDATAMASK: u32 = 1048575;
pub const NOTE_PCTRLMASK: i32 = -1048576;
pub const NOTE_EXIT_DETAIL_MASK: u32 = 458752;
pub const NOTE_EXIT_DECRYPTFAIL: u32 = 65536;
pub const NOTE_EXIT_MEMORY: u32 = 131072;
pub const NOTE_EXIT_CSERROR: u32 = 262144;
pub const NOTE_VM_PRESSURE: u32 = 2147483648;
pub const NOTE_VM_PRESSURE_TERMINATE: u32 = 1073741824;
pub const NOTE_VM_PRESSURE_SUDDEN_TERMINATE: u32 = 536870912;
pub const NOTE_VM_ERROR: u32 = 268435456;
pub const NOTE_SECONDS: u32 = 1;
pub const NOTE_USECONDS: u32 = 2;
pub const NOTE_NSECONDS: u32 = 4;
pub const NOTE_ABSOLUTE: u32 = 8;
pub const NOTE_LEEWAY: u32 = 16;
pub const NOTE_CRITICAL: u32 = 32;
pub const NOTE_BACKGROUND: u32 = 64;
pub const NOTE_MACH_CONTINUOUS_TIME: u32 = 128;
pub const NOTE_MACHTIME: u32 = 256;
pub const NOTE_TRACK: u32 = 1;
pub const NOTE_TRACKERR: u32 = 2;
pub const NOTE_CHILD: u32 = 4;
pub const IF_NAMESIZE: u32 = 16;
pub const APPLE_IF_FAM_LOOPBACK: u32 = 1;
pub const APPLE_IF_FAM_ETHERNET: u32 = 2;
pub const APPLE_IF_FAM_SLIP: u32 = 3;
pub const APPLE_IF_FAM_TUN: u32 = 4;
pub const APPLE_IF_FAM_VLAN: u32 = 5;
pub const APPLE_IF_FAM_PPP: u32 = 6;
pub const APPLE_IF_FAM_PVC: u32 = 7;
pub const APPLE_IF_FAM_DISC: u32 = 8;
pub const APPLE_IF_FAM_MDECAP: u32 = 9;
pub const APPLE_IF_FAM_GIF: u32 = 10;
pub const APPLE_IF_FAM_FAITH: u32 = 11;
pub const APPLE_IF_FAM_STF: u32 = 12;
pub const APPLE_IF_FAM_FIREWIRE: u32 = 13;
pub const APPLE_IF_FAM_BOND: u32 = 14;
pub const IF_MINMTU: u32 = 72;
pub const IF_MAXMTU: u32 = 65535;
pub const IFNAMSIZ: u32 = 16;
pub const IFF_UP: u32 = 1;
pub const IFF_BROADCAST: u32 = 2;
pub const IFF_DEBUG: u32 = 4;
pub const IFF_LOOPBACK: u32 = 8;
pub const IFF_POINTOPOINT: u32 = 16;
pub const IFF_NOTRAILERS: u32 = 32;
pub const IFF_RUNNING: u32 = 64;
pub const IFF_NOARP: u32 = 128;
pub const IFF_PROMISC: u32 = 256;
pub const IFF_ALLMULTI: u32 = 512;
pub const IFF_OACTIVE: u32 = 1024;
pub const IFF_SIMPLEX: u32 = 2048;
pub const IFF_LINK0: u32 = 4096;
pub const IFF_LINK1: u32 = 8192;
pub const IFF_LINK2: u32 = 16384;
pub const IFF_ALTPHYS: u32 = 16384;
pub const IFF_MULTICAST: u32 = 32768;
pub const IFCAP_RXCSUM: u32 = 1;
pub const IFCAP_TXCSUM: u32 = 2;
pub const IFCAP_VLAN_MTU: u32 = 4;
pub const IFCAP_VLAN_HWTAGGING: u32 = 8;
pub const IFCAP_JUMBO_MTU: u32 = 16;
pub const IFCAP_TSO4: u32 = 32;
pub const IFCAP_TSO6: u32 = 64;
pub const IFCAP_LRO: u32 = 128;
pub const IFCAP_AV: u32 = 256;
pub const IFCAP_TXSTATUS: u32 = 512;
pub const IFCAP_SKYWALK: u32 = 1024;
pub const IFCAP_HW_TIMESTAMP: u32 = 2048;
pub const IFCAP_SW_TIMESTAMP: u32 = 4096;
pub const IFCAP_CSUM_PARTIAL: u32 = 8192;
pub const IFCAP_CSUM_ZERO_INVERT: u32 = 16384;
pub const IFCAP_HWCSUM: u32 = 3;
pub const IFCAP_TSO: u32 = 96;
pub const IFCAP_VALID: u32 = 32767;
pub const IFQ_MAXLEN: u32 = 128;
pub const IFNET_SLOWHZ: u32 = 1;
pub const IFQ_TARGET_DELAY: u32 = 10000000;
pub const IFQ_UPDATE_INTERVAL: u32 = 100000000;
pub const IF_WAKE_ON_MAGIC_PACKET: u32 = 1;
pub const IFRTYPE_FUNCTIONAL_UNKNOWN: u32 = 0;
pub const IFRTYPE_FUNCTIONAL_LOOPBACK: u32 = 1;
pub const IFRTYPE_FUNCTIONAL_WIRED: u32 = 2;
pub const IFRTYPE_FUNCTIONAL_WIFI_INFRA: u32 = 3;
pub const IFRTYPE_FUNCTIONAL_WIFI_AWDL: u32 = 4;
pub const IFRTYPE_FUNCTIONAL_CELLULAR: u32 = 5;
pub const IFRTYPE_FUNCTIONAL_INTCOPROC: u32 = 6;
pub const IFRTYPE_FUNCTIONAL_LAST: u32 = 6;
pub const IFSTATMAX: u32 = 800;
pub const RTM_RTTUNIT: u32 = 1000000;
pub const RTF_UP: u32 = 1;
pub const RTF_GATEWAY: u32 = 2;
pub const RTF_HOST: u32 = 4;
pub const RTF_REJECT: u32 = 8;
pub const RTF_DYNAMIC: u32 = 16;
pub const RTF_MODIFIED: u32 = 32;
pub const RTF_DONE: u32 = 64;
pub const RTF_DELCLONE: u32 = 128;
pub const RTF_CLONING: u32 = 256;
pub const RTF_XRESOLVE: u32 = 512;
pub const RTF_LLINFO: u32 = 1024;
pub const RTF_LLDATA: u32 = 1024;
pub const RTF_STATIC: u32 = 2048;
pub const RTF_BLACKHOLE: u32 = 4096;
pub const RTF_NOIFREF: u32 = 8192;
pub const RTF_PROTO2: u32 = 16384;
pub const RTF_PROTO1: u32 = 32768;
pub const RTF_PRCLONING: u32 = 65536;
pub const RTF_WASCLONED: u32 = 131072;
pub const RTF_PROTO3: u32 = 262144;
pub const RTF_PINNED: u32 = 1048576;
pub const RTF_LOCAL: u32 = 2097152;
pub const RTF_BROADCAST: u32 = 4194304;
pub const RTF_MULTICAST: u32 = 8388608;
pub const RTF_IFSCOPE: u32 = 16777216;
pub const RTF_CONDEMNED: u32 = 33554432;
pub const RTF_IFREF: u32 = 67108864;
pub const RTF_PROXY: u32 = 134217728;
pub const RTF_ROUTER: u32 = 268435456;
pub const RTF_DEAD: u32 = 536870912;
pub const RTPRF_OURS: u32 = 262144;
pub const RTF_BITS : & 'static [ u8 ; 216usize ] = b"\x10\x01UP\x02GATEWAY\x03HOST\x04REJECT\x05DYNAMIC\x06MODIFIED\x07DONE\x08DELCLONE\tCLONING\nXRESOLVE\x0BLLINFO\x0CSTATIC\rBLACKHOLE\x0ENOIFREF\x0FPROTO2\x10PROTO1\x11PRCLONING\x12WASCLONED\x13PROTO3\x15PINNED\x16LOCAL\x17BROADCAST\x18MULTICAST\x19IFSCOPE\x1ACONDEMNED\x1BIFREF\x1CPROXY\x1DROUTER\0" ;
pub const RTM_VERSION: u32 = 5;
pub const RTM_ADD: u32 = 1;
pub const RTM_DELETE: u32 = 2;
pub const RTM_CHANGE: u32 = 3;
pub const RTM_GET: u32 = 4;
pub const RTM_LOSING: u32 = 5;
pub const RTM_REDIRECT: u32 = 6;
pub const RTM_MISS: u32 = 7;
pub const RTM_LOCK: u32 = 8;
pub const RTM_OLDADD: u32 = 9;
pub const RTM_OLDDEL: u32 = 10;
pub const RTM_RESOLVE: u32 = 11;
pub const RTM_NEWADDR: u32 = 12;
pub const RTM_DELADDR: u32 = 13;
pub const RTM_IFINFO: u32 = 14;
pub const RTM_NEWMADDR: u32 = 15;
pub const RTM_DELMADDR: u32 = 16;
pub const RTM_IFINFO2: u32 = 18;
pub const RTM_NEWMADDR2: u32 = 19;
pub const RTM_GET2: u32 = 20;
pub const RTV_MTU: u32 = 1;
pub const RTV_HOPCOUNT: u32 = 2;
pub const RTV_EXPIRE: u32 = 4;
pub const RTV_RPIPE: u32 = 8;
pub const RTV_SPIPE: u32 = 16;
pub const RTV_SSTHRESH: u32 = 32;
pub const RTV_RTT: u32 = 64;
pub const RTV_RTTVAR: u32 = 128;
pub const RTA_DST: u32 = 1;
pub const RTA_GATEWAY: u32 = 2;
pub const RTA_NETMASK: u32 = 4;
pub const RTA_GENMASK: u32 = 8;
pub const RTA_IFP: u32 = 16;
pub const RTA_IFA: u32 = 32;
pub const RTA_AUTHOR: u32 = 64;
pub const RTA_BRD: u32 = 128;
pub const RTAX_DST: u32 = 0;
pub const RTAX_GATEWAY: u32 = 1;
pub const RTAX_NETMASK: u32 = 2;
pub const RTAX_GENMASK: u32 = 3;
pub const RTAX_IFP: u32 = 4;
pub const RTAX_IFA: u32 = 5;
pub const RTAX_AUTHOR: u32 = 6;
pub const RTAX_BRD: u32 = 7;
pub const RTAX_MAX: u32 = 8;
pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_HOPOPTS: u32 = 0;
pub const IPPROTO_ICMP: u32 = 1;
pub const IPPROTO_IGMP: u32 = 2;
pub const IPPROTO_GGP: u32 = 3;
pub const IPPROTO_IPV4: u32 = 4;
pub const IPPROTO_IPIP: u32 = 4;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_ST: u32 = 7;
pub const IPPROTO_EGP: u32 = 8;
pub const IPPROTO_PIGP: u32 = 9;
pub const IPPROTO_RCCMON: u32 = 10;
pub const IPPROTO_NVPII: u32 = 11;
pub const IPPROTO_PUP: u32 = 12;
pub const IPPROTO_ARGUS: u32 = 13;
pub const IPPROTO_EMCON: u32 = 14;
pub const IPPROTO_XNET: u32 = 15;
pub const IPPROTO_CHAOS: u32 = 16;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_MUX: u32 = 18;
pub const IPPROTO_MEAS: u32 = 19;
pub const IPPROTO_HMP: u32 = 20;
pub const IPPROTO_PRM: u32 = 21;
pub const IPPROTO_IDP: u32 = 22;
pub const IPPROTO_TRUNK1: u32 = 23;
pub const IPPROTO_TRUNK2: u32 = 24;
pub const IPPROTO_LEAF1: u32 = 25;
pub const IPPROTO_LEAF2: u32 = 26;
pub const IPPROTO_RDP: u32 = 27;
pub const IPPROTO_IRTP: u32 = 28;
pub const IPPROTO_TP: u32 = 29;
pub const IPPROTO_BLT: u32 = 30;
pub const IPPROTO_NSP: u32 = 31;
pub const IPPROTO_INP: u32 = 32;
pub const IPPROTO_SEP: u32 = 33;
pub const IPPROTO_3PC: u32 = 34;
pub const IPPROTO_IDPR: u32 = 35;
pub const IPPROTO_XTP: u32 = 36;
pub const IPPROTO_DDP: u32 = 37;
pub const IPPROTO_CMTP: u32 = 38;
pub const IPPROTO_TPXX: u32 = 39;
pub const IPPROTO_IL: u32 = 40;
pub const IPPROTO_IPV6: u32 = 41;
pub const IPPROTO_SDRP: u32 = 42;
pub const IPPROTO_ROUTING: u32 = 43;
pub const IPPROTO_FRAGMENT: u32 = 44;
pub const IPPROTO_IDRP: u32 = 45;
pub const IPPROTO_RSVP: u32 = 46;
pub const IPPROTO_GRE: u32 = 47;
pub const IPPROTO_MHRP: u32 = 48;
pub const IPPROTO_BHA: u32 = 49;
pub const IPPROTO_ESP: u32 = 50;
pub const IPPROTO_AH: u32 = 51;
pub const IPPROTO_INLSP: u32 = 52;
pub const IPPROTO_SWIPE: u32 = 53;
pub const IPPROTO_NHRP: u32 = 54;
pub const IPPROTO_ICMPV6: u32 = 58;
pub const IPPROTO_NONE: u32 = 59;
pub const IPPROTO_DSTOPTS: u32 = 60;
pub const IPPROTO_AHIP: u32 = 61;
pub const IPPROTO_CFTP: u32 = 62;
pub const IPPROTO_HELLO: u32 = 63;
pub const IPPROTO_SATEXPAK: u32 = 64;
pub const IPPROTO_KRYPTOLAN: u32 = 65;
pub const IPPROTO_RVD: u32 = 66;
pub const IPPROTO_IPPC: u32 = 67;
pub const IPPROTO_ADFS: u32 = 68;
pub const IPPROTO_SATMON: u32 = 69;
pub const IPPROTO_VISA: u32 = 70;
pub const IPPROTO_IPCV: u32 = 71;
pub const IPPROTO_CPNX: u32 = 72;
pub const IPPROTO_CPHB: u32 = 73;
pub const IPPROTO_WSN: u32 = 74;
pub const IPPROTO_PVP: u32 = 75;
pub const IPPROTO_BRSATMON: u32 = 76;
pub const IPPROTO_ND: u32 = 77;
pub const IPPROTO_WBMON: u32 = 78;
pub const IPPROTO_WBEXPAK: u32 = 79;
pub const IPPROTO_EON: u32 = 80;
pub const IPPROTO_VMTP: u32 = 81;
pub const IPPROTO_SVMTP: u32 = 82;
pub const IPPROTO_VINES: u32 = 83;
pub const IPPROTO_TTP: u32 = 84;
pub const IPPROTO_IGP: u32 = 85;
pub const IPPROTO_DGP: u32 = 86;
pub const IPPROTO_TCF: u32 = 87;
pub const IPPROTO_IGRP: u32 = 88;
pub const IPPROTO_OSPFIGP: u32 = 89;
pub const IPPROTO_SRPC: u32 = 90;
pub const IPPROTO_LARP: u32 = 91;
pub const IPPROTO_MTP: u32 = 92;
pub const IPPROTO_AX25: u32 = 93;
pub const IPPROTO_IPEIP: u32 = 94;
pub const IPPROTO_MICP: u32 = 95;
pub const IPPROTO_SCCSP: u32 = 96;
pub const IPPROTO_ETHERIP: u32 = 97;
pub const IPPROTO_ENCAP: u32 = 98;
pub const IPPROTO_APES: u32 = 99;
pub const IPPROTO_GMTP: u32 = 100;
pub const IPPROTO_PIM: u32 = 103;
pub const IPPROTO_IPCOMP: u32 = 108;
pub const IPPROTO_PGM: u32 = 113;
pub const IPPROTO_SCTP: u32 = 132;
pub const IPPROTO_DIVERT: u32 = 254;
pub const IPPROTO_RAW: u32 = 255;
pub const IPPROTO_MAX: u32 = 256;
pub const IPPROTO_DONE: u32 = 257;
pub const __DARWIN_IPPORT_RESERVED: u32 = 1024;
pub const IPPORT_RESERVED: u32 = 1024;
pub const IPPORT_USERRESERVED: u32 = 5000;
pub const IPPORT_HIFIRSTAUTO: u32 = 49152;
pub const IPPORT_HILASTAUTO: u32 = 65535;
pub const IPPORT_RESERVEDSTART: u32 = 600;
pub const IN_CLASSA_NET: u32 = 4278190080;
pub const IN_CLASSA_NSHIFT: u32 = 24;
pub const IN_CLASSA_HOST: u32 = 16777215;
pub const IN_CLASSA_MAX: u32 = 128;
pub const IN_CLASSB_NET: u32 = 4294901760;
pub const IN_CLASSB_NSHIFT: u32 = 16;
pub const IN_CLASSB_HOST: u32 = 65535;
pub const IN_CLASSB_MAX: u32 = 65536;
pub const IN_CLASSC_NET: u32 = 4294967040;
pub const IN_CLASSC_NSHIFT: u32 = 8;
pub const IN_CLASSC_HOST: u32 = 255;
pub const IN_CLASSD_NET: u32 = 4026531840;
pub const IN_CLASSD_NSHIFT: u32 = 28;
pub const IN_CLASSD_HOST: u32 = 268435455;
pub const INADDR_NONE: u32 = 4294967295;
pub const IN_LOOPBACKNET: u32 = 127;
pub const INET_ADDRSTRLEN: u32 = 16;
pub const IP_OPTIONS: u32 = 1;
pub const IP_HDRINCL: u32 = 2;
pub const IP_TOS: u32 = 3;
pub const IP_TTL: u32 = 4;
pub const IP_RECVOPTS: u32 = 5;
pub const IP_RECVRETOPTS: u32 = 6;
pub const IP_RECVDSTADDR: u32 = 7;
pub const IP_RETOPTS: u32 = 8;
pub const IP_MULTICAST_IF: u32 = 9;
pub const IP_MULTICAST_TTL: u32 = 10;
pub const IP_MULTICAST_LOOP: u32 = 11;
pub const IP_ADD_MEMBERSHIP: u32 = 12;
pub const IP_DROP_MEMBERSHIP: u32 = 13;
pub const IP_MULTICAST_VIF: u32 = 14;
pub const IP_RSVP_ON: u32 = 15;
pub const IP_RSVP_OFF: u32 = 16;
pub const IP_RSVP_VIF_ON: u32 = 17;
pub const IP_RSVP_VIF_OFF: u32 = 18;
pub const IP_PORTRANGE: u32 = 19;
pub const IP_RECVIF: u32 = 20;
pub const IP_IPSEC_POLICY: u32 = 21;
pub const IP_FAITH: u32 = 22;
pub const IP_STRIPHDR: u32 = 23;
pub const IP_RECVTTL: u32 = 24;
pub const IP_BOUND_IF: u32 = 25;
pub const IP_PKTINFO: u32 = 26;
pub const IP_RECVPKTINFO: u32 = 26;
pub const IP_RECVTOS: u32 = 27;
pub const IP_FW_ADD: u32 = 40;
pub const IP_FW_DEL: u32 = 41;
pub const IP_FW_FLUSH: u32 = 42;
pub const IP_FW_ZERO: u32 = 43;
pub const IP_FW_GET: u32 = 44;
pub const IP_FW_RESETLOG: u32 = 45;
pub const IP_OLD_FW_ADD: u32 = 50;
pub const IP_OLD_FW_DEL: u32 = 51;
pub const IP_OLD_FW_FLUSH: u32 = 52;
pub const IP_OLD_FW_ZERO: u32 = 53;
pub const IP_OLD_FW_GET: u32 = 54;
pub const IP_NAT__XXX: u32 = 55;
pub const IP_OLD_FW_RESETLOG: u32 = 56;
pub const IP_DUMMYNET_CONFIGURE: u32 = 60;
pub const IP_DUMMYNET_DEL: u32 = 61;
pub const IP_DUMMYNET_FLUSH: u32 = 62;
pub const IP_DUMMYNET_GET: u32 = 64;
pub const IP_TRAFFIC_MGT_BACKGROUND: u32 = 65;
pub const IP_MULTICAST_IFINDEX: u32 = 66;
pub const IP_ADD_SOURCE_MEMBERSHIP: u32 = 70;
pub const IP_DROP_SOURCE_MEMBERSHIP: u32 = 71;
pub const IP_BLOCK_SOURCE: u32 = 72;
pub const IP_UNBLOCK_SOURCE: u32 = 73;
pub const IP_MSFILTER: u32 = 74;
pub const MCAST_JOIN_GROUP: u32 = 80;
pub const MCAST_LEAVE_GROUP: u32 = 81;
pub const MCAST_JOIN_SOURCE_GROUP: u32 = 82;
pub const MCAST_LEAVE_SOURCE_GROUP: u32 = 83;
pub const MCAST_BLOCK_SOURCE: u32 = 84;
pub const MCAST_UNBLOCK_SOURCE: u32 = 85;
pub const IP_DEFAULT_MULTICAST_TTL: u32 = 1;
pub const IP_DEFAULT_MULTICAST_LOOP: u32 = 1;
pub const IP_MIN_MEMBERSHIPS: u32 = 31;
pub const IP_MAX_MEMBERSHIPS: u32 = 4095;
pub const IP_MAX_GROUP_SRC_FILTER: u32 = 512;
pub const IP_MAX_SOCK_SRC_FILTER: u32 = 128;
pub const IP_MAX_SOCK_MUTE_FILTER: u32 = 128;
pub const MCAST_UNDEFINED: u32 = 0;
pub const MCAST_INCLUDE: u32 = 1;
pub const MCAST_EXCLUDE: u32 = 2;
pub const IP_PORTRANGE_DEFAULT: u32 = 0;
pub const IP_PORTRANGE_HIGH: u32 = 1;
pub const IP_PORTRANGE_LOW: u32 = 2;
pub const IPPROTO_MAXID: u32 = 52;
pub const IPCTL_FORWARDING: u32 = 1;
pub const IPCTL_SENDREDIRECTS: u32 = 2;
pub const IPCTL_DEFTTL: u32 = 3;
pub const IPCTL_RTEXPIRE: u32 = 5;
pub const IPCTL_RTMINEXPIRE: u32 = 6;
pub const IPCTL_RTMAXCACHE: u32 = 7;
pub const IPCTL_SOURCEROUTE: u32 = 8;
pub const IPCTL_DIRECTEDBROADCAST: u32 = 9;
pub const IPCTL_INTRQMAXLEN: u32 = 10;
pub const IPCTL_INTRQDROPS: u32 = 11;
pub const IPCTL_STATS: u32 = 12;
pub const IPCTL_ACCEPTSOURCEROUTE: u32 = 13;
pub const IPCTL_FASTFORWARDING: u32 = 14;
pub const IPCTL_KEEPFAITH: u32 = 15;
pub const IPCTL_GIF_TTL: u32 = 16;
pub const IPCTL_MAXID: u32 = 17;
pub const __KAME_VERSION: &'static [u8; 18usize] = b"2009/apple-darwin\0";
pub const IPV6PORT_RESERVED: u32 = 1024;
pub const IPV6PORT_ANONMIN: u32 = 49152;
pub const IPV6PORT_ANONMAX: u32 = 65535;
pub const IPV6PORT_RESERVEDMIN: u32 = 600;
pub const IPV6PORT_RESERVEDMAX: u32 = 1023;
pub const INET6_ADDRSTRLEN: u32 = 46;
pub const __IPV6_ADDR_SCOPE_NODELOCAL: u32 = 1;
pub const __IPV6_ADDR_SCOPE_INTFACELOCAL: u32 = 1;
pub const __IPV6_ADDR_SCOPE_LINKLOCAL: u32 = 2;
pub const __IPV6_ADDR_SCOPE_SITELOCAL: u32 = 5;
pub const __IPV6_ADDR_SCOPE_ORGLOCAL: u32 = 8;
pub const __IPV6_ADDR_SCOPE_GLOBAL: u32 = 14;
pub const IPV6_SOCKOPT_RESERVED1: u32 = 3;
pub const IPV6_UNICAST_HOPS: u32 = 4;
pub const IPV6_MULTICAST_IF: u32 = 9;
pub const IPV6_MULTICAST_HOPS: u32 = 10;
pub const IPV6_MULTICAST_LOOP: u32 = 11;
pub const IPV6_JOIN_GROUP: u32 = 12;
pub const IPV6_LEAVE_GROUP: u32 = 13;
pub const IPV6_PORTRANGE: u32 = 14;
pub const ICMP6_FILTER: u32 = 18;
pub const IPV6_2292PKTINFO: u32 = 19;
pub const IPV6_2292HOPLIMIT: u32 = 20;
pub const IPV6_2292NEXTHOP: u32 = 21;
pub const IPV6_2292HOPOPTS: u32 = 22;
pub const IPV6_2292DSTOPTS: u32 = 23;
pub const IPV6_2292RTHDR: u32 = 24;
pub const IPV6_2292PKTOPTIONS: u32 = 25;
pub const IPV6_CHECKSUM: u32 = 26;
pub const IPV6_V6ONLY: u32 = 27;
pub const IPV6_BINDV6ONLY: u32 = 27;
pub const IPV6_IPSEC_POLICY: u32 = 28;
pub const IPV6_FAITH: u32 = 29;
pub const IPV6_FW_ADD: u32 = 30;
pub const IPV6_FW_DEL: u32 = 31;
pub const IPV6_FW_FLUSH: u32 = 32;
pub const IPV6_FW_ZERO: u32 = 33;
pub const IPV6_FW_GET: u32 = 34;
pub const IPV6_RECVTCLASS: u32 = 35;
pub const IPV6_TCLASS: u32 = 36;
pub const IPV6_BOUND_IF: u32 = 125;
pub const IPV6_RTHDR_LOOSE: u32 = 0;
pub const IPV6_RTHDR_STRICT: u32 = 1;
pub const IPV6_RTHDR_TYPE_0: u32 = 0;
pub const IPV6_DEFAULT_MULTICAST_HOPS: u32 = 1;
pub const IPV6_DEFAULT_MULTICAST_LOOP: u32 = 1;
pub const IPV6_MIN_MEMBERSHIPS: u32 = 31;
pub const IPV6_MAX_MEMBERSHIPS: u32 = 4095;
pub const IPV6_MAX_GROUP_SRC_FILTER: u32 = 512;
pub const IPV6_MAX_SOCK_SRC_FILTER: u32 = 128;
pub const IPV6_PORTRANGE_DEFAULT: u32 = 0;
pub const IPV6_PORTRANGE_HIGH: u32 = 1;
pub const IPV6_PORTRANGE_LOW: u32 = 2;
pub const IPV6PROTO_MAXID: u32 = 104;
pub const IPV6CTL_FORWARDING: u32 = 1;
pub const IPV6CTL_SENDREDIRECTS: u32 = 2;
pub const IPV6CTL_DEFHLIM: u32 = 3;
pub const IPV6CTL_FORWSRCRT: u32 = 5;
pub const IPV6CTL_STATS: u32 = 6;
pub const IPV6CTL_MRTSTATS: u32 = 7;
pub const IPV6CTL_MRTPROTO: u32 = 8;
pub const IPV6CTL_MAXFRAGPACKETS: u32 = 9;
pub const IPV6CTL_SOURCECHECK: u32 = 10;
pub const IPV6CTL_SOURCECHECK_LOGINT: u32 = 11;
pub const IPV6CTL_ACCEPT_RTADV: u32 = 12;
pub const IPV6CTL_KEEPFAITH: u32 = 13;
pub const IPV6CTL_LOG_INTERVAL: u32 = 14;
pub const IPV6CTL_HDRNESTLIMIT: u32 = 15;
pub const IPV6CTL_DAD_COUNT: u32 = 16;
pub const IPV6CTL_AUTO_FLOWLABEL: u32 = 17;
pub const IPV6CTL_DEFMCASTHLIM: u32 = 18;
pub const IPV6CTL_GIF_HLIM: u32 = 19;
pub const IPV6CTL_KAME_VERSION: u32 = 20;
pub const IPV6CTL_USE_DEPRECATED: u32 = 21;
pub const IPV6CTL_RR_PRUNE: u32 = 22;
pub const IPV6CTL_V6ONLY: u32 = 24;
pub const IPV6CTL_RTEXPIRE: u32 = 25;
pub const IPV6CTL_RTMINEXPIRE: u32 = 26;
pub const IPV6CTL_RTMAXCACHE: u32 = 27;
pub const IPV6CTL_USETEMPADDR: u32 = 32;
pub const IPV6CTL_TEMPPLTIME: u32 = 33;
pub const IPV6CTL_TEMPVLTIME: u32 = 34;
pub const IPV6CTL_AUTO_LINKLOCAL: u32 = 35;
pub const IPV6CTL_RIP6STATS: u32 = 36;
pub const IPV6CTL_PREFER_TEMPADDR: u32 = 37;
pub const IPV6CTL_ADDRCTLPOLICY: u32 = 38;
pub const IPV6CTL_USE_DEFAULTZONE: u32 = 39;
pub const IPV6CTL_MAXFRAGS: u32 = 41;
pub const IPV6CTL_MCAST_PMTU: u32 = 44;
pub const IPV6CTL_NEIGHBORGCTHRESH: u32 = 46;
pub const IPV6CTL_MAXIFPREFIXES: u32 = 47;
pub const IPV6CTL_MAXIFDEFROUTERS: u32 = 48;
pub const IPV6CTL_MAXDYNROUTES: u32 = 49;
pub const ICMPV6CTL_ND6_ONLINKNSRFC4861: u32 = 50;
pub const IPV6CTL_MAXID: u32 = 51;
pub const TH_FIN: u32 = 1;
pub const TH_SYN: u32 = 2;
pub const TH_RST: u32 = 4;
pub const TH_PUSH: u32 = 8;
pub const TH_ACK: u32 = 16;
pub const TH_URG: u32 = 32;
pub const TH_ECE: u32 = 64;
pub const TH_CWR: u32 = 128;
pub const TH_FLAGS: u32 = 247;
pub const TCPOPT_EOL: u32 = 0;
pub const TCPOPT_NOP: u32 = 1;
pub const TCPOPT_MAXSEG: u32 = 2;
pub const TCPOLEN_MAXSEG: u32 = 4;
pub const TCPOPT_WINDOW: u32 = 3;
pub const TCPOLEN_WINDOW: u32 = 3;
pub const TCPOPT_SACK_PERMITTED: u32 = 4;
pub const TCPOLEN_SACK_PERMITTED: u32 = 2;
pub const TCPOPT_SACK: u32 = 5;
pub const TCPOLEN_SACK: u32 = 8;
pub const TCPOPT_TIMESTAMP: u32 = 8;
pub const TCPOLEN_TIMESTAMP: u32 = 10;
pub const TCPOLEN_TSTAMP_APPA: u32 = 12;
pub const TCPOPT_TSTAMP_HDR: u32 = 16844810;
pub const MAX_TCPOPTLEN: u32 = 40;
pub const TCPOPT_CC: u32 = 11;
pub const TCPOPT_CCNEW: u32 = 12;
pub const TCPOPT_CCECHO: u32 = 13;
pub const TCPOLEN_CC: u32 = 6;
pub const TCPOLEN_CC_APPA: u32 = 8;
pub const TCPOPT_SIGNATURE: u32 = 19;
pub const TCPOLEN_SIGNATURE: u32 = 18;
pub const TCPOPT_FASTOPEN: u32 = 34;
pub const TCPOLEN_FASTOPEN_REQ: u32 = 2;
pub const TCPOPT_SACK_HDR: u32 = 16844032;
pub const MAX_SACK_BLKS: u32 = 6;
pub const TCP_MAX_SACK: u32 = 4;
pub const TCP_MSS: u32 = 512;
pub const TCP_MINMSS: u32 = 216;
pub const TCP6_MSS: u32 = 1024;
pub const TCP_MAXWIN: u32 = 65535;
pub const TTCP_CLIENT_SND_WND: u32 = 4096;
pub const TCP_MAX_WINSHIFT: u32 = 14;
pub const TCP_MAXHLEN: u32 = 60;
pub const TCP_NODELAY: u32 = 1;
pub const TCP_MAXSEG: u32 = 2;
pub const TCP_NOPUSH: u32 = 4;
pub const TCP_NOOPT: u32 = 8;
pub const TCP_KEEPALIVE: u32 = 16;
pub const TCP_CONNECTIONTIMEOUT: u32 = 32;
pub const PERSIST_TIMEOUT: u32 = 64;
pub const TCP_RXT_CONNDROPTIME: u32 = 128;
pub const TCP_RXT_FINDROP: u32 = 256;
pub const TCP_KEEPINTVL: u32 = 257;
pub const TCP_KEEPCNT: u32 = 258;
pub const TCP_SENDMOREACKS: u32 = 259;
pub const TCP_ENABLE_ECN: u32 = 260;
pub const TCP_FASTOPEN: u32 = 261;
pub const TCP_CONNECTION_INFO: u32 = 262;
pub const TCP_NOTSENT_LOWAT: u32 = 513;
pub const TCPCI_OPT_TIMESTAMPS: u32 = 1;
pub const TCPCI_OPT_SACK: u32 = 2;
pub const TCPCI_OPT_WSCALE: u32 = 4;
pub const TCPCI_OPT_ECN: u32 = 8;
pub const TCPCI_FLAG_LOSSRECOVERY: u32 = 1;
pub const TCPCI_FLAG_REORDERING_DETECTED: u32 = 2;
pub const CPU_STATE_MAX: u32 = 4;
pub const CPU_STATE_USER: u32 = 0;
pub const CPU_STATE_SYSTEM: u32 = 1;
pub const CPU_STATE_IDLE: u32 = 2;
pub const CPU_STATE_NICE: u32 = 3;
pub const CPU_ARCH_MASK: u32 = 4278190080;
pub const CPU_ARCH_ABI64: u32 = 16777216;
pub const CPU_SUBTYPE_MASK: u32 = 4278190080;
pub const CPU_SUBTYPE_LIB64: u32 = 2147483648;
pub const CPU_SUBTYPE_INTEL_FAMILY_MAX: u32 = 15;
pub const CPU_SUBTYPE_INTEL_MODEL_ALL: u32 = 0;
pub const CPUFAMILY_UNKNOWN: u32 = 0;
pub const CPUFAMILY_POWERPC_G3: u32 = 3471054153;
pub const CPUFAMILY_POWERPC_G4: u32 = 2009171118;
pub const CPUFAMILY_POWERPC_G5: u32 = 3983988906;
pub const CPUFAMILY_INTEL_6_13: u32 = 2855483691;
pub const CPUFAMILY_INTEL_PENRYN: u32 = 2028621756;
pub const CPUFAMILY_INTEL_NEHALEM: u32 = 1801080018;
pub const CPUFAMILY_INTEL_WESTMERE: u32 = 1463508716;
pub const CPUFAMILY_INTEL_SANDYBRIDGE: u32 = 1418770316;
pub const CPUFAMILY_INTEL_IVYBRIDGE: u32 = 526772277;
pub const CPUFAMILY_INTEL_HASWELL: u32 = 280134364;
pub const CPUFAMILY_INTEL_BROADWELL: u32 = 1479463068;
pub const CPUFAMILY_INTEL_SKYLAKE: u32 = 939270559;
pub const CPUFAMILY_INTEL_KABYLAKE: u32 = 260141638;
pub const CPUFAMILY_ARM_9: u32 = 3878847406;
pub const CPUFAMILY_ARM_11: u32 = 2415272152;
pub const CPUFAMILY_ARM_XSCALE: u32 = 1404044789;
pub const CPUFAMILY_ARM_12: u32 = 3172666089;
pub const CPUFAMILY_ARM_13: u32 = 214503012;
pub const CPUFAMILY_ARM_14: u32 = 2517073649;
pub const CPUFAMILY_ARM_15: u32 = 2823887818;
pub const CPUFAMILY_ARM_SWIFT: u32 = 506291073;
pub const CPUFAMILY_ARM_CYCLONE: u32 = 933271106;
pub const CPUFAMILY_ARM_TYPHOON: u32 = 747742334;
pub const CPUFAMILY_ARM_TWISTER: u32 = 2465937352;
pub const CPUFAMILY_ARM_HURRICANE: u32 = 1741614739;
pub const CPUFAMILY_ARM_MONSOON_MISTRAL: u32 = 3894312694;
pub const CPUFAMILY_INTEL_6_23: u32 = 2028621756;
pub const CPUFAMILY_INTEL_6_26: u32 = 1801080018;
pub const PROC_ALL_PIDS: u32 = 1;
pub const PROC_PGRP_ONLY: u32 = 2;
pub const PROC_TTY_ONLY: u32 = 3;
pub const PROC_UID_ONLY: u32 = 4;
pub const PROC_RUID_ONLY: u32 = 5;
pub const PROC_PPID_ONLY: u32 = 6;
pub const PROC_KDBG_ONLY: u32 = 7;
pub const PROC_FLAG_SYSTEM: u32 = 1;
pub const PROC_FLAG_TRACED: u32 = 2;
pub const PROC_FLAG_INEXIT: u32 = 4;
pub const PROC_FLAG_PPWAIT: u32 = 8;
pub const PROC_FLAG_LP64: u32 = 16;
pub const PROC_FLAG_SLEADER: u32 = 32;
pub const PROC_FLAG_CTTY: u32 = 64;
pub const PROC_FLAG_CONTROLT: u32 = 128;
pub const PROC_FLAG_THCWD: u32 = 256;
pub const PROC_FLAG_PC_THROTTLE: u32 = 512;
pub const PROC_FLAG_PC_SUSP: u32 = 1024;
pub const PROC_FLAG_PC_KILL: u32 = 1536;
pub const PROC_FLAG_PC_MASK: u32 = 1536;
pub const PROC_FLAG_PA_THROTTLE: u32 = 2048;
pub const PROC_FLAG_PA_SUSP: u32 = 4096;
pub const PROC_FLAG_PSUGID: u32 = 8192;
pub const PROC_FLAG_EXEC: u32 = 16384;
pub const MAXTHREADNAMESIZE: u32 = 64;
pub const PROC_REGION_SUBMAP: u32 = 1;
pub const PROC_REGION_SHARED: u32 = 2;
pub const SM_COW: u32 = 1;
pub const SM_PRIVATE: u32 = 2;
pub const SM_EMPTY: u32 = 3;
pub const SM_SHARED: u32 = 4;
pub const SM_TRUESHARED: u32 = 5;
pub const SM_PRIVATE_ALIASED: u32 = 6;
pub const SM_SHARED_ALIASED: u32 = 7;
pub const SM_LARGE_PAGE: u32 = 8;
pub const TH_STATE_RUNNING: u32 = 1;
pub const TH_STATE_STOPPED: u32 = 2;
pub const TH_STATE_WAITING: u32 = 3;
pub const TH_STATE_UNINTERRUPTIBLE: u32 = 4;
pub const TH_STATE_HALTED: u32 = 5;
pub const TH_FLAGS_SWAPPED: u32 = 1;
pub const TH_FLAGS_IDLE: u32 = 2;
pub const WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT: u32 = 1;
pub const WQ_EXCEEDED_TOTAL_THREAD_LIMIT: u32 = 2;
pub const WQ_FLAGS_AVAILABLE: u32 = 4;
pub const PROC_FP_SHARED: u32 = 1;
pub const PROC_FP_CLEXEC: u32 = 2;
pub const PROC_FP_GUARDED: u32 = 4;
pub const PROC_FP_CLFORK: u32 = 8;
pub const PROC_FI_GUARD_CLOSE: u32 = 1;
pub const PROC_FI_GUARD_DUP: u32 = 2;
pub const PROC_FI_GUARD_SOCKET_IPC: u32 = 4;
pub const PROC_FI_GUARD_FILEPORT: u32 = 8;
pub const INI_IPV4: u32 = 1;
pub const INI_IPV6: u32 = 2;
pub const TSI_T_REXMT: u32 = 0;
pub const TSI_T_PERSIST: u32 = 1;
pub const TSI_T_KEEP: u32 = 2;
pub const TSI_T_2MSL: u32 = 3;
pub const TSI_T_NTIMERS: u32 = 4;
pub const TSI_S_CLOSED: u32 = 0;
pub const TSI_S_LISTEN: u32 = 1;
pub const TSI_S_SYN_SENT: u32 = 2;
pub const TSI_S_SYN_RECEIVED: u32 = 3;
pub const TSI_S_ESTABLISHED: u32 = 4;
pub const TSI_S__CLOSE_WAIT: u32 = 5;
pub const TSI_S_FIN_WAIT_1: u32 = 6;
pub const TSI_S_CLOSING: u32 = 7;
pub const TSI_S_LAST_ACK: u32 = 8;
pub const TSI_S_FIN_WAIT_2: u32 = 9;
pub const TSI_S_TIME_WAIT: u32 = 10;
pub const TSI_S_RESERVED: u32 = 11;
pub const SOI_S_NOFDREF: u32 = 1;
pub const SOI_S_ISCONNECTED: u32 = 2;
pub const SOI_S_ISCONNECTING: u32 = 4;
pub const SOI_S_ISDISCONNECTING: u32 = 8;
pub const SOI_S_CANTSENDMORE: u32 = 16;
pub const SOI_S_CANTRCVMORE: u32 = 32;
pub const SOI_S_RCVATMARK: u32 = 64;
pub const SOI_S_PRIV: u32 = 128;
pub const SOI_S_NBIO: u32 = 256;
pub const SOI_S_ASYNC: u32 = 512;
pub const SOI_S_INCOMP: u32 = 2048;
pub const SOI_S_COMP: u32 = 4096;
pub const SOI_S_ISDISCONNECTED: u32 = 8192;
pub const SOI_S_DRAINING: u32 = 16384;
pub const PROC_KQUEUE_SELECT: u32 = 1;
pub const PROC_KQUEUE_SLEEP: u32 = 2;
pub const PROC_KQUEUE_32: u32 = 8;
pub const PROC_KQUEUE_64: u32 = 16;
pub const PROC_KQUEUE_QOS: u32 = 32;
pub const PROX_FDTYPE_ATALK: u32 = 0;
pub const PROX_FDTYPE_VNODE: u32 = 1;
pub const PROX_FDTYPE_SOCKET: u32 = 2;
pub const PROX_FDTYPE_PSHM: u32 = 3;
pub const PROX_FDTYPE_PSEM: u32 = 4;
pub const PROX_FDTYPE_KQUEUE: u32 = 5;
pub const PROX_FDTYPE_PIPE: u32 = 6;
pub const PROX_FDTYPE_FSEVENTS: u32 = 7;
pub const PROX_FDTYPE_NETPOLICY: u32 = 9;
pub const PROC_PIDLISTFDS: u32 = 1;
pub const PROC_PIDTASKALLINFO: u32 = 2;
pub const PROC_PIDTBSDINFO: u32 = 3;
pub const PROC_PIDTASKINFO: u32 = 4;
pub const PROC_PIDTHREADINFO: u32 = 5;
pub const PROC_PIDLISTTHREADS: u32 = 6;
pub const PROC_PIDREGIONINFO: u32 = 7;
pub const PROC_PIDREGIONPATHINFO: u32 = 8;
pub const PROC_PIDVNODEPATHINFO: u32 = 9;
pub const PROC_PIDTHREADPATHINFO: u32 = 10;
pub const PROC_PIDPATHINFO: u32 = 11;
pub const PROC_PIDPATHINFO_SIZE: u32 = 1024;
pub const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
pub const PROC_PIDWORKQUEUEINFO: u32 = 12;
pub const PROC_PIDT_SHORTBSDINFO: u32 = 13;
pub const PROC_PIDLISTFILEPORTS: u32 = 14;
pub const PROC_PIDTHREADID64INFO: u32 = 15;
pub const PROC_PID_RUSAGE: u32 = 16;
pub const PROC_PID_RUSAGE_SIZE: u32 = 0;
pub const PROC_PIDFDVNODEINFO: u32 = 1;
pub const PROC_PIDFDVNODEPATHINFO: u32 = 2;
pub const PROC_PIDFDSOCKETINFO: u32 = 3;
pub const PROC_PIDFDPSEMINFO: u32 = 4;
pub const PROC_PIDFDPSHMINFO: u32 = 5;
pub const PROC_PIDFDPIPEINFO: u32 = 6;
pub const PROC_PIDFDKQUEUEINFO: u32 = 7;
pub const PROC_PIDFDATALKINFO: u32 = 8;
pub const PROC_PIDFILEPORTVNODEPATHINFO: u32 = 2;
pub const PROC_PIDFILEPORTSOCKETINFO: u32 = 3;
pub const PROC_PIDFILEPORTPSHMINFO: u32 = 5;
pub const PROC_PIDFILEPORTPIPEINFO: u32 = 6;
pub const PROC_SELFSET_PCONTROL: u32 = 1;
pub const PROC_SELFSET_THREADNAME: u32 = 2;
pub const PROC_SELFSET_THREADNAME_SIZE: u32 = 63;
pub const PROC_SELFSET_VMRSRCOWNER: u32 = 3;
pub const PROC_SELFSET_DELAYIDLESLEEP: u32 = 4;
pub const PROC_DIRTYCONTROL_TRACK: u32 = 1;
pub const PROC_DIRTYCONTROL_SET: u32 = 2;
pub const PROC_DIRTYCONTROL_GET: u32 = 3;
pub const PROC_DIRTYCONTROL_CLEAR: u32 = 4;
pub const PROC_DIRTY_TRACK: u32 = 1;
pub const PROC_DIRTY_ALLOW_IDLE_EXIT: u32 = 2;
pub const PROC_DIRTY_DEFER: u32 = 4;
pub const PROC_DIRTY_LAUNCH_IN_PROGRESS: u32 = 8;
pub const PROC_DIRTY_TRACKED: u32 = 1;
pub const PROC_DIRTY_ALLOWS_IDLE_EXIT: u32 = 2;
pub const PROC_DIRTY_IS_DIRTY: u32 = 4;
pub const PROC_DIRTY_LAUNCH_IS_IN_PROGRESS: u32 = 8;
pub const PROC_UDATA_INFO_GET: u32 = 1;
pub const PROC_UDATA_INFO_SET: u32 = 2;
pub const PROC_LISTPIDSPATH_PATH_IS_VOLUME: u32 = 1;
pub const PROC_LISTPIDSPATH_EXCLUDE_EVTONLY: u32 = 2;
pub const PROC_SETPC_NONE: u32 = 0;
pub const PROC_SETPC_THROTTLEMEM: u32 = 1;
pub const PROC_SETPC_SUSPEND: u32 = 2;
pub const PROC_SETPC_TERMINATE: u32 = 3;
pub type __int8_t = ::std::os::raw::c_schar;
pub type __uint8_t = ::std::os::raw::c_uchar;
pub type __int16_t = ::std::os::raw::c_short;
pub type __uint16_t = ::std::os::raw::c_ushort;
pub type __int32_t = ::std::os::raw::c_int;
pub type __uint32_t = ::std::os::raw::c_uint;
pub type __int64_t = ::std::os::raw::c_longlong;
pub type __uint64_t = ::std::os::raw::c_ulonglong;
pub type __darwin_intptr_t = ::std::os::raw::c_long;
pub type __darwin_natural_t = ::std::os::raw::c_uint;
pub type __darwin_ct_rune_t = ::std::os::raw::c_int;
#[repr(C)]
#[derive(Copy, Clone)]
pub union __mbstate_t {
    pub __mbstate8: [::std::os::raw::c_char; 128usize],
    pub _mbstateL: ::std::os::raw::c_longlong,
    _bindgen_union_align: [u64; 16usize],
}
pub type __darwin_mbstate_t = __mbstate_t;
pub type __darwin_ptrdiff_t = ::std::os::raw::c_long;
pub type __darwin_size_t = ::std::os::raw::c_ulong;
pub type __darwin_va_list = __builtin_va_list;
pub type __darwin_wchar_t = ::std::os::raw::c_int;
pub type __darwin_rune_t = __darwin_wchar_t;
pub type __darwin_wint_t = ::std::os::raw::c_int;
pub type __darwin_clock_t = ::std::os::raw::c_ulong;
pub type __darwin_socklen_t = __uint32_t;
pub type __darwin_ssize_t = ::std::os::raw::c_long;
pub type __darwin_time_t = ::std::os::raw::c_long;
pub type __darwin_blkcnt_t = __int64_t;
pub type __darwin_blksize_t = __int32_t;
pub type __darwin_dev_t = __int32_t;
pub type __darwin_fsblkcnt_t = ::std::os::raw::c_uint;
pub type __darwin_fsfilcnt_t = ::std::os::raw::c_uint;
pub type __darwin_gid_t = __uint32_t;
pub type __darwin_id_t = __uint32_t;
pub type __darwin_ino64_t = __uint64_t;
pub type __darwin_ino_t = __darwin_ino64_t;
pub type __darwin_mach_port_name_t = __darwin_natural_t;
pub type __darwin_mach_port_t = __darwin_mach_port_name_t;
pub type __darwin_mode_t = __uint16_t;
pub type __darwin_off_t = __int64_t;
pub type __darwin_pid_t = __int32_t;
pub type __darwin_sigset_t = __uint32_t;
pub type __darwin_suseconds_t = __int32_t;
pub type __darwin_uid_t = __uint32_t;
pub type __darwin_useconds_t = __uint32_t;
pub type __darwin_uuid_t = [::std::os::raw::c_uchar; 16usize];
pub type __darwin_uuid_string_t = [::std::os::raw::c_char; 37usize];
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_pthread_handler_rec {
    pub __routine: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
    pub __arg: *mut ::std::os::raw::c_void,
    pub __next: *mut __darwin_pthread_handler_rec,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct _opaque_pthread_attr_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 56usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct _opaque_pthread_cond_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 40usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _opaque_pthread_condattr_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 8usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct _opaque_pthread_mutex_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 56usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _opaque_pthread_mutexattr_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 8usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _opaque_pthread_once_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 8usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct _opaque_pthread_rwlock_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 192usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _opaque_pthread_rwlockattr_t {
    pub __sig: ::std::os::raw::c_long,
    pub __opaque: [::std::os::raw::c_char; 16usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct _opaque_pthread_t {
    pub __sig: ::std::os::raw::c_long,
    pub __cleanup_stack: *mut __darwin_pthread_handler_rec,
    pub __opaque: [::std::os::raw::c_char; 8176usize],
}
pub type __darwin_pthread_attr_t = _opaque_pthread_attr_t;
pub type __darwin_pthread_cond_t = _opaque_pthread_cond_t;
pub type __darwin_pthread_condattr_t = _opaque_pthread_condattr_t;
pub type __darwin_pthread_key_t = ::std::os::raw::c_ulong;
pub type __darwin_pthread_mutex_t = _opaque_pthread_mutex_t;
pub type __darwin_pthread_mutexattr_t = _opaque_pthread_mutexattr_t;
pub type __darwin_pthread_once_t = _opaque_pthread_once_t;
pub type __darwin_pthread_rwlock_t = _opaque_pthread_rwlock_t;
pub type __darwin_pthread_rwlockattr_t = _opaque_pthread_rwlockattr_t;
pub type __darwin_pthread_t = *mut _opaque_pthread_t;
pub type u_int8_t = ::std::os::raw::c_uchar;
pub type u_int16_t = ::std::os::raw::c_ushort;
pub type u_int32_t = ::std::os::raw::c_uint;
pub type u_int64_t = ::std::os::raw::c_ulonglong;
pub type register_t = i64;
pub type user_addr_t = u_int64_t;
pub type user_size_t = u_int64_t;
pub type user_ssize_t = i64;
pub type user_long_t = i64;
pub type user_ulong_t = u_int64_t;
pub type user_time_t = i64;
pub type user_off_t = i64;
pub type syscall_arg_t = u_int64_t;
pub type u_char = ::std::os::raw::c_uchar;
pub type u_short = ::std::os::raw::c_ushort;
pub type u_int = ::std::os::raw::c_uint;
pub type u_long = ::std::os::raw::c_ulong;
pub type ushort = ::std::os::raw::c_ushort;
pub type uint = ::std::os::raw::c_uint;
pub type u_quad_t = u_int64_t;
pub type quad_t = i64;
pub type qaddr_t = *mut quad_t;
pub type caddr_t = *mut ::std::os::raw::c_char;
pub type daddr_t = i32;
pub type dev_t = __darwin_dev_t;
pub type fixpt_t = u_int32_t;
pub type blkcnt_t = __darwin_blkcnt_t;
pub type blksize_t = __darwin_blksize_t;
pub type gid_t = __darwin_gid_t;
pub type in_addr_t = __uint32_t;
pub type in_port_t = __uint16_t;
pub type ino_t = __darwin_ino_t;
pub type ino64_t = __darwin_ino64_t;
pub type key_t = __int32_t;
pub type mode_t = __darwin_mode_t;
pub type nlink_t = __uint16_t;
pub type id_t = __darwin_id_t;
pub type pid_t = __darwin_pid_t;
pub type off_t = __darwin_off_t;
pub type segsz_t = i32;
pub type swblk_t = i32;
pub type uid_t = __darwin_uid_t;
pub type clock_t = __darwin_clock_t;
pub type size_t = __darwin_size_t;
pub type ssize_t = __darwin_ssize_t;
pub type time_t = __darwin_time_t;
pub type useconds_t = __darwin_useconds_t;
pub type suseconds_t = __darwin_suseconds_t;
pub type rsize_t = __darwin_size_t;
pub type errno_t = ::std::os::raw::c_int;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fd_set {
    pub fds_bits: [__int32_t; 32usize],
}
pub type fd_mask = __int32_t;
pub type pthread_attr_t = __darwin_pthread_attr_t;
pub type pthread_cond_t = __darwin_pthread_cond_t;
pub type pthread_condattr_t = __darwin_pthread_condattr_t;
pub type pthread_mutex_t = __darwin_pthread_mutex_t;
pub type pthread_mutexattr_t = __darwin_pthread_mutexattr_t;
pub type pthread_once_t = __darwin_pthread_once_t;
pub type pthread_rwlock_t = __darwin_pthread_rwlock_t;
pub type pthread_rwlockattr_t = __darwin_pthread_rwlockattr_t;
pub type pthread_t = __darwin_pthread_t;
pub type pthread_key_t = __darwin_pthread_key_t;
pub type fsblkcnt_t = __darwin_fsblkcnt_t;
pub type fsfilcnt_t = __darwin_fsfilcnt_t;
pub type sig_atomic_t = ::std::os::raw::c_int;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_i386_thread_state {
    pub __eax: ::std::os::raw::c_uint,
    pub __ebx: ::std::os::raw::c_uint,
    pub __ecx: ::std::os::raw::c_uint,
    pub __edx: ::std::os::raw::c_uint,
    pub __edi: ::std::os::raw::c_uint,
    pub __esi: ::std::os::raw::c_uint,
    pub __ebp: ::std::os::raw::c_uint,
    pub __esp: ::std::os::raw::c_uint,
    pub __ss: ::std::os::raw::c_uint,
    pub __eflags: ::std::os::raw::c_uint,
    pub __eip: ::std::os::raw::c_uint,
    pub __cs: ::std::os::raw::c_uint,
    pub __ds: ::std::os::raw::c_uint,
    pub __es: ::std::os::raw::c_uint,
    pub __fs: ::std::os::raw::c_uint,
    pub __gs: ::std::os::raw::c_uint,
}
#[repr(C)]
#[repr(align(2))]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_fp_control {
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize], u8>,
}
pub type __darwin_fp_control_t = __darwin_fp_control;
#[repr(C)]
#[repr(align(2))]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_fp_status {
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize], u8>,
}
#[test]
fn bindgen_test_layout___darwin_fp_status() {
    assert_eq!(
        ::std::mem::size_of::<__darwin_fp_status>(),
        2usize,
        concat!("Size of: ", stringify!(__darwin_fp_status))
    );
    assert_eq!(
        ::std::mem::align_of::<__darwin_fp_status>(),
        2usize,
        concat!("Alignment of ", stringify!(__darwin_fp_status))
    );
}
impl __darwin_fp_status {
    #[inline]
    pub fn __invalid(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___invalid(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __denorm(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(1usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___denorm(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(1usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __zdiv(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(2usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___zdiv(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(2usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __ovrfl(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(3usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___ovrfl(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(3usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __undfl(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___undfl(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __precis(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(5usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___precis(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(5usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __stkflt(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(6usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___stkflt(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(6usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __errsumm(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(7usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___errsumm(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(7usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __c0(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(8usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___c0(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(8usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __c1(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(9usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___c1(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(9usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __c2(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(10usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___c2(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(10usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __tos(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(11usize, 3u8) as u16) }
    }
    #[inline]
    pub fn set___tos(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(11usize, 3u8, val as u64)
        }
    }
    #[inline]
    pub fn __c3(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(14usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___c3(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(14usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __busy(&self) -> ::std::os::raw::c_ushort {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(15usize, 1u8) as u16) }
    }
    #[inline]
    pub fn set___busy(&mut self, val: ::std::os::raw::c_ushort) {
        unsafe {
            let val: u16 = ::std::mem::transmute(val);
            self._bitfield_1.set(15usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        __invalid: ::std::os::raw::c_ushort,
        __denorm: ::std::os::raw::c_ushort,
        __zdiv: ::std::os::raw::c_ushort,
        __ovrfl: ::std::os::raw::c_ushort,
        __undfl: ::std::os::raw::c_ushort,
        __precis: ::std::os::raw::c_ushort,
        __stkflt: ::std::os::raw::c_ushort,
        __errsumm: ::std::os::raw::c_ushort,
        __c0: ::std::os::raw::c_ushort,
        __c1: ::std::os::raw::c_ushort,
        __c2: ::std::os::raw::c_ushort,
        __tos: ::std::os::raw::c_ushort,
        __c3: ::std::os::raw::c_ushort,
        __busy: ::std::os::raw::c_ushort,
    ) -> __BindgenBitfieldUnit<[u8; 2usize], u8> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 2usize], u8> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let __invalid: u16 = unsafe { ::std::mem::transmute(__invalid) };
            __invalid as u64
        });
        __bindgen_bitfield_unit.set(1usize, 1u8, {
            let __denorm: u16 = unsafe { ::std::mem::transmute(__denorm) };
            __denorm as u64
        });
        __bindgen_bitfield_unit.set(2usize, 1u8, {
            let __zdiv: u16 = unsafe { ::std::mem::transmute(__zdiv) };
            __zdiv as u64
        });
        __bindgen_bitfield_unit.set(3usize, 1u8, {
            let __ovrfl: u16 = unsafe { ::std::mem::transmute(__ovrfl) };
            __ovrfl as u64
        });
        __bindgen_bitfield_unit.set(4usize, 1u8, {
            let __undfl: u16 = unsafe { ::std::mem::transmute(__undfl) };
            __undfl as u64
        });
        __bindgen_bitfield_unit.set(5usize, 1u8, {
            let __precis: u16 = unsafe { ::std::mem::transmute(__precis) };
            __precis as u64
        });
        __bindgen_bitfield_unit.set(6usize, 1u8, {
            let __stkflt: u16 = unsafe { ::std::mem::transmute(__stkflt) };
            __stkflt as u64
        });
        __bindgen_bitfield_unit.set(7usize, 1u8, {
            let __errsumm: u16 = unsafe { ::std::mem::transmute(__errsumm) };
            __errsumm as u64
        });
        __bindgen_bitfield_unit.set(8usize, 1u8, {
            let __c0: u16 = unsafe { ::std::mem::transmute(__c0) };
            __c0 as u64
        });
        __bindgen_bitfield_unit.set(9usize, 1u8, {
            let __c1: u16 = unsafe { ::std::mem::transmute(__c1) };
            __c1 as u64
        });
        __bindgen_bitfield_unit.set(10usize, 1u8, {
            let __c2: u16 = unsafe { ::std::mem::transmute(__c2) };
            __c2 as u64
        });
        __bindgen_bitfield_unit.set(11usize, 3u8, {
            let __tos: u16 = unsafe { ::std::mem::transmute(__tos) };
            __tos as u64
        });
        __bindgen_bitfield_unit.set(14usize, 1u8, {
            let __c3: u16 = unsafe { ::std::mem::transmute(__c3) };
            __c3 as u64
        });
        __bindgen_bitfield_unit.set(15usize, 1u8, {
            let __busy: u16 = unsafe { ::std::mem::transmute(__busy) };
            __busy as u64
        });
        __bindgen_bitfield_unit
    }
}
pub type __darwin_fp_status_t = __darwin_fp_status;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_mmst_reg {
    pub __mmst_reg: [::std::os::raw::c_char; 10usize],
    pub __mmst_rsrv: [::std::os::raw::c_char; 6usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_xmm_reg {
    pub __xmm_reg: [::std::os::raw::c_char; 16usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_ymm_reg {
    pub __ymm_reg: [::std::os::raw::c_char; 32usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_zmm_reg {
    pub __zmm_reg: [::std::os::raw::c_char; 64usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_opmask_reg {
    pub __opmask_reg: [::std::os::raw::c_char; 8usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_i386_float_state {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 224usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_i386_avx_state {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 224usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
    pub __avx_reserved1: [::std::os::raw::c_char; 64usize],
    pub __fpu_ymmh0: __darwin_xmm_reg,
    pub __fpu_ymmh1: __darwin_xmm_reg,
    pub __fpu_ymmh2: __darwin_xmm_reg,
    pub __fpu_ymmh3: __darwin_xmm_reg,
    pub __fpu_ymmh4: __darwin_xmm_reg,
    pub __fpu_ymmh5: __darwin_xmm_reg,
    pub __fpu_ymmh6: __darwin_xmm_reg,
    pub __fpu_ymmh7: __darwin_xmm_reg,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_i386_avx512_state {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 224usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
    pub __avx_reserved1: [::std::os::raw::c_char; 64usize],
    pub __fpu_ymmh0: __darwin_xmm_reg,
    pub __fpu_ymmh1: __darwin_xmm_reg,
    pub __fpu_ymmh2: __darwin_xmm_reg,
    pub __fpu_ymmh3: __darwin_xmm_reg,
    pub __fpu_ymmh4: __darwin_xmm_reg,
    pub __fpu_ymmh5: __darwin_xmm_reg,
    pub __fpu_ymmh6: __darwin_xmm_reg,
    pub __fpu_ymmh7: __darwin_xmm_reg,
    pub __fpu_k0: __darwin_opmask_reg,
    pub __fpu_k1: __darwin_opmask_reg,
    pub __fpu_k2: __darwin_opmask_reg,
    pub __fpu_k3: __darwin_opmask_reg,
    pub __fpu_k4: __darwin_opmask_reg,
    pub __fpu_k5: __darwin_opmask_reg,
    pub __fpu_k6: __darwin_opmask_reg,
    pub __fpu_k7: __darwin_opmask_reg,
    pub __fpu_zmmh0: __darwin_ymm_reg,
    pub __fpu_zmmh1: __darwin_ymm_reg,
    pub __fpu_zmmh2: __darwin_ymm_reg,
    pub __fpu_zmmh3: __darwin_ymm_reg,
    pub __fpu_zmmh4: __darwin_ymm_reg,
    pub __fpu_zmmh5: __darwin_ymm_reg,
    pub __fpu_zmmh6: __darwin_ymm_reg,
    pub __fpu_zmmh7: __darwin_ymm_reg,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_i386_exception_state {
    pub __trapno: __uint16_t,
    pub __cpu: __uint16_t,
    pub __err: __uint32_t,
    pub __faultvaddr: __uint32_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_x86_debug_state32 {
    pub __dr0: ::std::os::raw::c_uint,
    pub __dr1: ::std::os::raw::c_uint,
    pub __dr2: ::std::os::raw::c_uint,
    pub __dr3: ::std::os::raw::c_uint,
    pub __dr4: ::std::os::raw::c_uint,
    pub __dr5: ::std::os::raw::c_uint,
    pub __dr6: ::std::os::raw::c_uint,
    pub __dr7: ::std::os::raw::c_uint,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_x86_thread_state64 {
    pub __rax: __uint64_t,
    pub __rbx: __uint64_t,
    pub __rcx: __uint64_t,
    pub __rdx: __uint64_t,
    pub __rdi: __uint64_t,
    pub __rsi: __uint64_t,
    pub __rbp: __uint64_t,
    pub __rsp: __uint64_t,
    pub __r8: __uint64_t,
    pub __r9: __uint64_t,
    pub __r10: __uint64_t,
    pub __r11: __uint64_t,
    pub __r12: __uint64_t,
    pub __r13: __uint64_t,
    pub __r14: __uint64_t,
    pub __r15: __uint64_t,
    pub __rip: __uint64_t,
    pub __rflags: __uint64_t,
    pub __cs: __uint64_t,
    pub __fs: __uint64_t,
    pub __gs: __uint64_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_x86_float_state64 {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_xmm8: __darwin_xmm_reg,
    pub __fpu_xmm9: __darwin_xmm_reg,
    pub __fpu_xmm10: __darwin_xmm_reg,
    pub __fpu_xmm11: __darwin_xmm_reg,
    pub __fpu_xmm12: __darwin_xmm_reg,
    pub __fpu_xmm13: __darwin_xmm_reg,
    pub __fpu_xmm14: __darwin_xmm_reg,
    pub __fpu_xmm15: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 96usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_x86_avx_state64 {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_xmm8: __darwin_xmm_reg,
    pub __fpu_xmm9: __darwin_xmm_reg,
    pub __fpu_xmm10: __darwin_xmm_reg,
    pub __fpu_xmm11: __darwin_xmm_reg,
    pub __fpu_xmm12: __darwin_xmm_reg,
    pub __fpu_xmm13: __darwin_xmm_reg,
    pub __fpu_xmm14: __darwin_xmm_reg,
    pub __fpu_xmm15: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 96usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
    pub __avx_reserved1: [::std::os::raw::c_char; 64usize],
    pub __fpu_ymmh0: __darwin_xmm_reg,
    pub __fpu_ymmh1: __darwin_xmm_reg,
    pub __fpu_ymmh2: __darwin_xmm_reg,
    pub __fpu_ymmh3: __darwin_xmm_reg,
    pub __fpu_ymmh4: __darwin_xmm_reg,
    pub __fpu_ymmh5: __darwin_xmm_reg,
    pub __fpu_ymmh6: __darwin_xmm_reg,
    pub __fpu_ymmh7: __darwin_xmm_reg,
    pub __fpu_ymmh8: __darwin_xmm_reg,
    pub __fpu_ymmh9: __darwin_xmm_reg,
    pub __fpu_ymmh10: __darwin_xmm_reg,
    pub __fpu_ymmh11: __darwin_xmm_reg,
    pub __fpu_ymmh12: __darwin_xmm_reg,
    pub __fpu_ymmh13: __darwin_xmm_reg,
    pub __fpu_ymmh14: __darwin_xmm_reg,
    pub __fpu_ymmh15: __darwin_xmm_reg,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_x86_avx512_state64 {
    pub __fpu_reserved: [::std::os::raw::c_int; 2usize],
    pub __fpu_fcw: __darwin_fp_control,
    pub __fpu_fsw: __darwin_fp_status,
    pub __fpu_ftw: __uint8_t,
    pub __fpu_rsrv1: __uint8_t,
    pub __fpu_fop: __uint16_t,
    pub __fpu_ip: __uint32_t,
    pub __fpu_cs: __uint16_t,
    pub __fpu_rsrv2: __uint16_t,
    pub __fpu_dp: __uint32_t,
    pub __fpu_ds: __uint16_t,
    pub __fpu_rsrv3: __uint16_t,
    pub __fpu_mxcsr: __uint32_t,
    pub __fpu_mxcsrmask: __uint32_t,
    pub __fpu_stmm0: __darwin_mmst_reg,
    pub __fpu_stmm1: __darwin_mmst_reg,
    pub __fpu_stmm2: __darwin_mmst_reg,
    pub __fpu_stmm3: __darwin_mmst_reg,
    pub __fpu_stmm4: __darwin_mmst_reg,
    pub __fpu_stmm5: __darwin_mmst_reg,
    pub __fpu_stmm6: __darwin_mmst_reg,
    pub __fpu_stmm7: __darwin_mmst_reg,
    pub __fpu_xmm0: __darwin_xmm_reg,
    pub __fpu_xmm1: __darwin_xmm_reg,
    pub __fpu_xmm2: __darwin_xmm_reg,
    pub __fpu_xmm3: __darwin_xmm_reg,
    pub __fpu_xmm4: __darwin_xmm_reg,
    pub __fpu_xmm5: __darwin_xmm_reg,
    pub __fpu_xmm6: __darwin_xmm_reg,
    pub __fpu_xmm7: __darwin_xmm_reg,
    pub __fpu_xmm8: __darwin_xmm_reg,
    pub __fpu_xmm9: __darwin_xmm_reg,
    pub __fpu_xmm10: __darwin_xmm_reg,
    pub __fpu_xmm11: __darwin_xmm_reg,
    pub __fpu_xmm12: __darwin_xmm_reg,
    pub __fpu_xmm13: __darwin_xmm_reg,
    pub __fpu_xmm14: __darwin_xmm_reg,
    pub __fpu_xmm15: __darwin_xmm_reg,
    pub __fpu_rsrv4: [::std::os::raw::c_char; 96usize],
    pub __fpu_reserved1: ::std::os::raw::c_int,
    pub __avx_reserved1: [::std::os::raw::c_char; 64usize],
    pub __fpu_ymmh0: __darwin_xmm_reg,
    pub __fpu_ymmh1: __darwin_xmm_reg,
    pub __fpu_ymmh2: __darwin_xmm_reg,
    pub __fpu_ymmh3: __darwin_xmm_reg,
    pub __fpu_ymmh4: __darwin_xmm_reg,
    pub __fpu_ymmh5: __darwin_xmm_reg,
    pub __fpu_ymmh6: __darwin_xmm_reg,
    pub __fpu_ymmh7: __darwin_xmm_reg,
    pub __fpu_ymmh8: __darwin_xmm_reg,
    pub __fpu_ymmh9: __darwin_xmm_reg,
    pub __fpu_ymmh10: __darwin_xmm_reg,
    pub __fpu_ymmh11: __darwin_xmm_reg,
    pub __fpu_ymmh12: __darwin_xmm_reg,
    pub __fpu_ymmh13: __darwin_xmm_reg,
    pub __fpu_ymmh14: __darwin_xmm_reg,
    pub __fpu_ymmh15: __darwin_xmm_reg,
    pub __fpu_k0: __darwin_opmask_reg,
    pub __fpu_k1: __darwin_opmask_reg,
    pub __fpu_k2: __darwin_opmask_reg,
    pub __fpu_k3: __darwin_opmask_reg,
    pub __fpu_k4: __darwin_opmask_reg,
    pub __fpu_k5: __darwin_opmask_reg,
    pub __fpu_k6: __darwin_opmask_reg,
    pub __fpu_k7: __darwin_opmask_reg,
    pub __fpu_zmmh0: __darwin_ymm_reg,
    pub __fpu_zmmh1: __darwin_ymm_reg,
    pub __fpu_zmmh2: __darwin_ymm_reg,
    pub __fpu_zmmh3: __darwin_ymm_reg,
    pub __fpu_zmmh4: __darwin_ymm_reg,
    pub __fpu_zmmh5: __darwin_ymm_reg,
    pub __fpu_zmmh6: __darwin_ymm_reg,
    pub __fpu_zmmh7: __darwin_ymm_reg,
    pub __fpu_zmmh8: __darwin_ymm_reg,
    pub __fpu_zmmh9: __darwin_ymm_reg,
    pub __fpu_zmmh10: __darwin_ymm_reg,
    pub __fpu_zmmh11: __darwin_ymm_reg,
    pub __fpu_zmmh12: __darwin_ymm_reg,
    pub __fpu_zmmh13: __darwin_ymm_reg,
    pub __fpu_zmmh14: __darwin_ymm_reg,
    pub __fpu_zmmh15: __darwin_ymm_reg,
    pub __fpu_zmm16: __darwin_zmm_reg,
    pub __fpu_zmm17: __darwin_zmm_reg,
    pub __fpu_zmm18: __darwin_zmm_reg,
    pub __fpu_zmm19: __darwin_zmm_reg,
    pub __fpu_zmm20: __darwin_zmm_reg,
    pub __fpu_zmm21: __darwin_zmm_reg,
    pub __fpu_zmm22: __darwin_zmm_reg,
    pub __fpu_zmm23: __darwin_zmm_reg,
    pub __fpu_zmm24: __darwin_zmm_reg,
    pub __fpu_zmm25: __darwin_zmm_reg,
    pub __fpu_zmm26: __darwin_zmm_reg,
    pub __fpu_zmm27: __darwin_zmm_reg,
    pub __fpu_zmm28: __darwin_zmm_reg,
    pub __fpu_zmm29: __darwin_zmm_reg,
    pub __fpu_zmm30: __darwin_zmm_reg,
    pub __fpu_zmm31: __darwin_zmm_reg,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_x86_exception_state64 {
    pub __trapno: __uint16_t,
    pub __cpu: __uint16_t,
    pub __err: __uint32_t,
    pub __faultvaddr: __uint64_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_x86_debug_state64 {
    pub __dr0: __uint64_t,
    pub __dr1: __uint64_t,
    pub __dr2: __uint64_t,
    pub __dr3: __uint64_t,
    pub __dr4: __uint64_t,
    pub __dr5: __uint64_t,
    pub __dr6: __uint64_t,
    pub __dr7: __uint64_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_x86_cpmu_state64 {
    pub __ctrs: [__uint64_t; 16usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext32 {
    pub __es: __darwin_i386_exception_state,
    pub __ss: __darwin_i386_thread_state,
    pub __fs: __darwin_i386_float_state,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext_avx32 {
    pub __es: __darwin_i386_exception_state,
    pub __ss: __darwin_i386_thread_state,
    pub __fs: __darwin_i386_avx_state,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext_avx512_32 {
    pub __es: __darwin_i386_exception_state,
    pub __ss: __darwin_i386_thread_state,
    pub __fs: __darwin_i386_avx512_state,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext64 {
    pub __es: __darwin_x86_exception_state64,
    pub __ss: __darwin_x86_thread_state64,
    pub __fs: __darwin_x86_float_state64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext_avx64 {
    pub __es: __darwin_x86_exception_state64,
    pub __ss: __darwin_x86_thread_state64,
    pub __fs: __darwin_x86_avx_state64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __darwin_mcontext_avx512_64 {
    pub __es: __darwin_x86_exception_state64,
    pub __ss: __darwin_x86_thread_state64,
    pub __fs: __darwin_x86_avx512_state64,
}
pub type mcontext_t = *mut __darwin_mcontext64;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_sigaltstack {
    pub ss_sp: *mut ::std::os::raw::c_void,
    pub ss_size: __darwin_size_t,
    pub ss_flags: ::std::os::raw::c_int,
}
pub type stack_t = __darwin_sigaltstack;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __darwin_ucontext {
    pub uc_onstack: ::std::os::raw::c_int,
    pub uc_sigmask: __darwin_sigset_t,
    pub uc_stack: __darwin_sigaltstack,
    pub uc_link: *mut __darwin_ucontext,
    pub uc_mcsize: __darwin_size_t,
    pub uc_mcontext: *mut __darwin_mcontext64,
}
pub type ucontext_t = __darwin_ucontext;
pub type sigset_t = __darwin_sigset_t;
#[repr(C)]
#[derive(Copy, Clone)]
pub union sigval {
    pub sival_int: ::std::os::raw::c_int,
    pub sival_ptr: *mut ::std::os::raw::c_void,
    _bindgen_union_align: u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigevent {
    pub sigev_notify: ::std::os::raw::c_int,
    pub sigev_signo: ::std::os::raw::c_int,
    pub sigev_value: sigval,
    pub sigev_notify_function: ::std::option::Option<unsafe extern "C" fn(arg1: sigval)>,
    pub sigev_notify_attributes: *mut pthread_attr_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __siginfo {
    pub si_signo: ::std::os::raw::c_int,
    pub si_errno: ::std::os::raw::c_int,
    pub si_code: ::std::os::raw::c_int,
    pub si_pid: pid_t,
    pub si_uid: uid_t,
    pub si_status: ::std::os::raw::c_int,
    pub si_addr: *mut ::std::os::raw::c_void,
    pub si_value: sigval,
    pub si_band: ::std::os::raw::c_long,
    pub __pad: [::std::os::raw::c_ulong; 7usize],
}
pub type siginfo_t = __siginfo;
#[repr(C)]
#[derive(Copy, Clone)]
pub union __sigaction_u {
    pub __sa_handler: ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>,
    pub __sa_sigaction: ::std::option::Option<
        unsafe extern "C" fn(
            arg1: ::std::os::raw::c_int,
            arg2: *mut __siginfo,
            arg3: *mut ::std::os::raw::c_void,
        ),
    >,
    _bindgen_union_align: u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct __sigaction {
    pub __sigaction_u: __sigaction_u,
    pub sa_tramp: ::std::option::Option<
        unsafe extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: ::std::os::raw::c_int,
            arg3: ::std::os::raw::c_int,
            arg4: *mut siginfo_t,
            arg5: *mut ::std::os::raw::c_void,
        ),
    >,
    pub sa_mask: sigset_t,
    pub sa_flags: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigaction {
    pub __sigaction_u: __sigaction_u,
    pub sa_mask: sigset_t,
    pub sa_flags: ::std::os::raw::c_int,
}
pub type sig_t = ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sigvec {
    pub sv_handler: ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>,
    pub sv_mask: ::std::os::raw::c_int,
    pub sv_flags: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sigstack {
    pub ss_sp: *mut ::std::os::raw::c_char,
    pub ss_onstack: ::std::os::raw::c_int,
}
extern "C" {
    pub fn signal(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>,
    ) -> ::std::option::Option<
        unsafe extern "C" fn(
            arg1: ::std::os::raw::c_int,
            arg2: ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>,
        ),
    >;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timespec {
    pub tv_sec: __darwin_time_t,
    pub tv_nsec: ::std::os::raw::c_long,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ostat {
    pub st_dev: __uint16_t,
    pub st_ino: ino_t,
    pub st_mode: mode_t,
    pub st_nlink: nlink_t,
    pub st_uid: __uint16_t,
    pub st_gid: __uint16_t,
    pub st_rdev: __uint16_t,
    pub st_size: __int32_t,
    pub st_atimespec: timespec,
    pub st_mtimespec: timespec,
    pub st_ctimespec: timespec,
    pub st_blksize: __int32_t,
    pub st_blocks: __int32_t,
    pub st_flags: __uint32_t,
    pub st_gen: __uint32_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_mode: mode_t,
    pub st_nlink: nlink_t,
    pub st_ino: __darwin_ino64_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub st_atimespec: timespec,
    pub st_mtimespec: timespec,
    pub st_ctimespec: timespec,
    pub st_birthtimespec: timespec,
    pub st_size: off_t,
    pub st_blocks: blkcnt_t,
    pub st_blksize: blksize_t,
    pub st_flags: __uint32_t,
    pub st_gen: __uint32_t,
    pub st_lspare: __int32_t,
    pub st_qspare: [__int64_t; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stat64 {
    pub st_dev: dev_t,
    pub st_mode: mode_t,
    pub st_nlink: nlink_t,
    pub st_ino: __darwin_ino64_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub st_atimespec: timespec,
    pub st_mtimespec: timespec,
    pub st_ctimespec: timespec,
    pub st_birthtimespec: timespec,
    pub st_size: off_t,
    pub st_blocks: blkcnt_t,
    pub st_blksize: blksize_t,
    pub st_flags: __uint32_t,
    pub st_gen: __uint32_t,
    pub st_lspare: __int32_t,
    pub st_qspare: [__int64_t; 2usize],
}
extern "C" {
    pub fn chmod(arg1: *const ::std::os::raw::c_char, arg2: mode_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fchmod(arg1: ::std::os::raw::c_int, arg2: mode_t) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_fstat$INODE64"]
    pub fn fstat(arg1: ::std::os::raw::c_int, arg2: *mut stat) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_lstat$INODE64"]
    pub fn lstat(arg1: *const ::std::os::raw::c_char, arg2: *mut stat) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mkdir(arg1: *const ::std::os::raw::c_char, arg2: mode_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mkfifo(arg1: *const ::std::os::raw::c_char, arg2: mode_t) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_stat$INODE64"]
    pub fn stat(arg1: *const ::std::os::raw::c_char, arg2: *mut stat) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mknod(
        arg1: *const ::std::os::raw::c_char,
        arg2: mode_t,
        arg3: dev_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn umask(arg1: mode_t) -> mode_t;
}
extern "C" {
    pub fn fchmodat(
        arg1: ::std::os::raw::c_int,
        arg2: *const ::std::os::raw::c_char,
        arg3: mode_t,
        arg4: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_fstatat$INODE64"]
    pub fn fstatat(
        arg1: ::std::os::raw::c_int,
        arg2: *const ::std::os::raw::c_char,
        arg3: *mut stat,
        arg4: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mkdirat(
        arg1: ::std::os::raw::c_int,
        arg2: *const ::std::os::raw::c_char,
        arg3: mode_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn futimens(__fd: ::std::os::raw::c_int, __times: *const timespec)
        -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn utimensat(
        __fd: ::std::os::raw::c_int,
        __path: *const ::std::os::raw::c_char,
        __times: *const timespec,
        __flag: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _filesec {
    _unused: [u8; 0],
}
pub type filesec_t = *mut _filesec;
extern "C" {
    pub fn chflags(arg1: *const ::std::os::raw::c_char, arg2: __uint32_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn chmodx_np(arg1: *const ::std::os::raw::c_char, arg2: filesec_t)
        -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fchflags(arg1: ::std::os::raw::c_int, arg2: __uint32_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fchmodx_np(arg1: ::std::os::raw::c_int, arg2: filesec_t) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_fstatx_np$INODE64"]
    pub fn fstatx_np(
        arg1: ::std::os::raw::c_int,
        arg2: *mut stat,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn lchflags(arg1: *const ::std::os::raw::c_char, arg2: __uint32_t)
        -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn lchmod(arg1: *const ::std::os::raw::c_char, arg2: mode_t) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_lstatx_np$INODE64"]
    pub fn lstatx_np(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut stat,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mkdirx_np(arg1: *const ::std::os::raw::c_char, arg2: filesec_t)
        -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mkfifox_np(
        arg1: *const ::std::os::raw::c_char,
        arg2: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_statx_np$INODE64"]
    pub fn statx_np(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut stat,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn umaskx_np(arg1: filesec_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fstatx64_np(
        arg1: ::std::os::raw::c_int,
        arg2: *mut stat64,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn lstatx64_np(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut stat64,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn statx64_np(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut stat64,
        arg3: filesec_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fstat64(arg1: ::std::os::raw::c_int, arg2: *mut stat64) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn lstat64(arg1: *const ::std::os::raw::c_char, arg2: *mut stat64)
        -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn stat64(arg1: *const ::std::os::raw::c_char, arg2: *mut stat64) -> ::std::os::raw::c_int;
}
pub type au_id_t = uid_t;
pub type au_asid_t = pid_t;
pub type au_event_t = u_int16_t;
pub type au_emod_t = u_int16_t;
pub type au_class_t = u_int32_t;
pub type au_asflgs_t = u_int64_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_tid {
    pub port: dev_t,
    pub machine: u_int32_t,
}
pub type au_tid_t = au_tid;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_tid_addr {
    pub at_port: dev_t,
    pub at_type: u_int32_t,
    pub at_addr: [u_int32_t; 4usize],
}
pub type au_tid_addr_t = au_tid_addr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_mask {
    pub am_success: ::std::os::raw::c_uint,
    pub am_failure: ::std::os::raw::c_uint,
}
pub type au_mask_t = au_mask;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auditinfo {
    pub ai_auid: au_id_t,
    pub ai_mask: au_mask_t,
    pub ai_termid: au_tid_t,
    pub ai_asid: au_asid_t,
}
pub type auditinfo_t = auditinfo;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auditinfo_addr {
    pub ai_auid: au_id_t,
    pub ai_mask: au_mask_t,
    pub ai_termid: au_tid_addr_t,
    pub ai_asid: au_asid_t,
    pub ai_flags: au_asflgs_t,
}
pub type auditinfo_addr_t = auditinfo_addr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auditpinfo {
    pub ap_pid: pid_t,
    pub ap_auid: au_id_t,
    pub ap_mask: au_mask_t,
    pub ap_termid: au_tid_t,
    pub ap_asid: au_asid_t,
}
pub type auditpinfo_t = auditpinfo;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auditpinfo_addr {
    pub ap_pid: pid_t,
    pub ap_auid: au_id_t,
    pub ap_mask: au_mask_t,
    pub ap_termid: au_tid_addr_t,
    pub ap_asid: au_asid_t,
    pub ap_flags: au_asflgs_t,
}
pub type auditpinfo_addr_t = auditpinfo_addr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_session {
    pub as_aia_p: *mut auditinfo_addr_t,
    pub as_mask: au_mask_t,
}
pub type au_session_t = au_session;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_token {
    _unused: [u8; 0],
}
pub type token_t = au_token;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_qctrl {
    pub aq_hiwater: ::std::os::raw::c_int,
    pub aq_lowater: ::std::os::raw::c_int,
    pub aq_bufsz: ::std::os::raw::c_int,
    pub aq_delay: ::std::os::raw::c_int,
    pub aq_minfree: ::std::os::raw::c_int,
}
pub type au_qctrl_t = au_qctrl;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct audit_stat {
    pub as_version: ::std::os::raw::c_uint,
    pub as_numevent: ::std::os::raw::c_uint,
    pub as_generated: ::std::os::raw::c_int,
    pub as_nonattrib: ::std::os::raw::c_int,
    pub as_kernel: ::std::os::raw::c_int,
    pub as_audit: ::std::os::raw::c_int,
    pub as_auditctl: ::std::os::raw::c_int,
    pub as_enqueue: ::std::os::raw::c_int,
    pub as_written: ::std::os::raw::c_int,
    pub as_wblocked: ::std::os::raw::c_int,
    pub as_rblocked: ::std::os::raw::c_int,
    pub as_dropped: ::std::os::raw::c_int,
    pub as_totalsize: ::std::os::raw::c_int,
    pub as_memused: ::std::os::raw::c_uint,
}
pub type au_stat_t = audit_stat;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct audit_fstat {
    pub af_filesz: u_int64_t,
    pub af_currsz: u_int64_t,
}
pub type au_fstat_t = audit_fstat;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct au_evclass_map {
    pub ec_number: au_event_t,
    pub ec_class: au_class_t,
}
pub type au_evclass_map_t = au_evclass_map;
extern "C" {
    pub fn audit(
        arg1: *const ::std::os::raw::c_void,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn auditon(
        arg1: ::std::os::raw::c_int,
        arg2: *mut ::std::os::raw::c_void,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn auditctl(arg1: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getauid(arg1: *mut au_id_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setauid(arg1: *const au_id_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getaudit_addr(
        arg1: *mut auditinfo_addr,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setaudit_addr(
        arg1: *const auditinfo_addr,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getaudit(arg1: *mut auditinfo) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setaudit(arg1: *const auditinfo) -> ::std::os::raw::c_int;
}
pub type int_least8_t = i8;
pub type int_least16_t = i16;
pub type int_least32_t = i32;
pub type int_least64_t = i64;
pub type uint_least8_t = u8;
pub type uint_least16_t = u16;
pub type uint_least32_t = u32;
pub type uint_least64_t = u64;
pub type int_fast8_t = i8;
pub type int_fast16_t = i16;
pub type int_fast32_t = i32;
pub type int_fast64_t = i64;
pub type uint_fast8_t = u8;
pub type uint_fast16_t = u16;
pub type uint_fast32_t = u32;
pub type uint_fast64_t = u64;
pub type intmax_t = ::std::os::raw::c_long;
pub type uintmax_t = ::std::os::raw::c_ulong;
pub type boolean_t = ::std::os::raw::c_uint;
pub type natural_t = __darwin_natural_t;
pub type integer_t = ::std::os::raw::c_int;
pub type vm_offset_t = usize;
pub type vm_size_t = usize;
pub type mach_vm_address_t = u64;
pub type mach_vm_offset_t = u64;
pub type mach_vm_size_t = u64;
pub type vm_map_offset_t = u64;
pub type vm_map_address_t = u64;
pub type vm_map_size_t = u64;
pub type mach_port_context_t = mach_vm_address_t;
pub type mach_port_name_t = natural_t;
pub type mach_port_name_array_t = *mut mach_port_name_t;
pub type mach_port_t = __darwin_mach_port_t;
pub type mach_port_array_t = *mut mach_port_t;
pub type mach_port_right_t = natural_t;
pub type mach_port_type_t = natural_t;
pub type mach_port_type_array_t = *mut mach_port_type_t;
pub type mach_port_urefs_t = natural_t;
pub type mach_port_delta_t = integer_t;
pub type mach_port_seqno_t = natural_t;
pub type mach_port_mscount_t = natural_t;
pub type mach_port_msgcount_t = natural_t;
pub type mach_port_rights_t = natural_t;
pub type mach_port_srights_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mach_port_status {
    pub mps_pset: mach_port_rights_t,
    pub mps_seqno: mach_port_seqno_t,
    pub mps_mscount: mach_port_mscount_t,
    pub mps_qlimit: mach_port_msgcount_t,
    pub mps_msgcount: mach_port_msgcount_t,
    pub mps_sorights: mach_port_rights_t,
    pub mps_srights: boolean_t,
    pub mps_pdrequest: boolean_t,
    pub mps_nsrequest: boolean_t,
    pub mps_flags: natural_t,
}
pub type mach_port_status_t = mach_port_status;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mach_port_limits {
    pub mpl_qlimit: mach_port_msgcount_t,
}
pub type mach_port_limits_t = mach_port_limits;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mach_port_info_ext {
    pub mpie_status: mach_port_status_t,
    pub mpie_boost_cnt: mach_port_msgcount_t,
    pub reserved: [u32; 6usize],
}
pub type mach_port_info_ext_t = mach_port_info_ext;
pub type mach_port_info_t = *mut integer_t;
pub type mach_port_flavor_t = ::std::os::raw::c_int;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mach_port_qos {
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize], u32>,
    pub len: natural_t,
}
impl mach_port_qos {
    #[inline]
    pub fn name(&self) -> ::std::os::raw::c_uint {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_name(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn prealloc(&self) -> ::std::os::raw::c_uint {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(1usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_prealloc(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(1usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn pad1(&self) -> boolean_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(2usize, 30u8) as u32) }
    }
    #[inline]
    pub fn set_pad1(&mut self, val: boolean_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(2usize, 30u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        name: ::std::os::raw::c_uint,
        prealloc: ::std::os::raw::c_uint,
        pad1: boolean_t,
    ) -> __BindgenBitfieldUnit<[u8; 4usize], u32> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 4usize], u32> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let name: u32 = unsafe { ::std::mem::transmute(name) };
            name as u64
        });
        __bindgen_bitfield_unit.set(1usize, 1u8, {
            let prealloc: u32 = unsafe { ::std::mem::transmute(prealloc) };
            prealloc as u64
        });
        __bindgen_bitfield_unit.set(2usize, 30u8, {
            let pad1: u32 = unsafe { ::std::mem::transmute(pad1) };
            pad1 as u64
        });
        __bindgen_bitfield_unit
    }
}
pub type mach_port_qos_t = mach_port_qos;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mach_port_options {
    pub flags: u32,
    pub mpl: mach_port_limits_t,
    pub reserved: [u64; 2usize],
}
pub type mach_port_options_t = mach_port_options;
pub type mach_port_options_ptr_t = *mut mach_port_options_t;
pub const mach_port_guard_exception_codes_kGUARD_EXC_DESTROY: mach_port_guard_exception_codes = 1;
pub const mach_port_guard_exception_codes_kGUARD_EXC_MOD_REFS: mach_port_guard_exception_codes = 2;
pub const mach_port_guard_exception_codes_kGUARD_EXC_SET_CONTEXT: mach_port_guard_exception_codes =
    4;
pub const mach_port_guard_exception_codes_kGUARD_EXC_UNGUARDED: mach_port_guard_exception_codes = 8;
pub const mach_port_guard_exception_codes_kGUARD_EXC_INCORRECT_GUARD:
    mach_port_guard_exception_codes = 16;
pub type mach_port_guard_exception_codes = u32;
extern "C" {
    pub fn audit_session_self() -> mach_port_name_t;
}
extern "C" {
    pub fn audit_session_join(port: mach_port_name_t) -> au_asid_t;
}
extern "C" {
    pub fn audit_session_port(
        asid: au_asid_t,
        portname: *mut mach_port_name_t,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct label {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ucred {
    pub cr_link: ucred__bindgen_ty_1,
    pub cr_ref: u_long,
    pub cr_posix: ucred_posix_cred,
    pub cr_label: *mut label,
    pub cr_audit: au_session,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ucred__bindgen_ty_1 {
    pub tqe_next: *mut ucred,
    pub tqe_prev: *mut *mut ucred,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ucred_posix_cred {
    pub cr_uid: uid_t,
    pub cr_ruid: uid_t,
    pub cr_svuid: uid_t,
    pub cr_ngroups: ::std::os::raw::c_short,
    pub cr_groups: [gid_t; 16usize],
    pub cr_rgid: gid_t,
    pub cr_svgid: gid_t,
    pub cr_gmuid: uid_t,
    pub cr_flags: ::std::os::raw::c_int,
}
pub type kauth_cred_t = *mut ucred;
pub type posix_cred_t = *mut ucred_posix_cred;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xucred {
    pub cr_version: u_int,
    pub cr_uid: uid_t,
    pub cr_ngroups: ::std::os::raw::c_short,
    pub cr_groups: [gid_t; 16usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timeval {
    pub tv_sec: __darwin_time_t,
    pub tv_usec: __darwin_suseconds_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timeval64 {
    pub tv_sec: __int64_t,
    pub tv_usec: __int64_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct itimerval {
    pub it_interval: timeval,
    pub it_value: timeval,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: ::std::os::raw::c_int,
    pub tz_dsttime: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct clockinfo {
    pub hz: ::std::os::raw::c_int,
    pub tick: ::std::os::raw::c_int,
    pub tickadj: ::std::os::raw::c_int,
    pub stathz: ::std::os::raw::c_int,
    pub profhz: ::std::os::raw::c_int,
}
pub type __darwin_nl_item = ::std::os::raw::c_int;
pub type __darwin_wctrans_t = ::std::os::raw::c_int;
pub type __darwin_wctype_t = __uint32_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tm {
    pub tm_sec: ::std::os::raw::c_int,
    pub tm_min: ::std::os::raw::c_int,
    pub tm_hour: ::std::os::raw::c_int,
    pub tm_mday: ::std::os::raw::c_int,
    pub tm_mon: ::std::os::raw::c_int,
    pub tm_year: ::std::os::raw::c_int,
    pub tm_wday: ::std::os::raw::c_int,
    pub tm_yday: ::std::os::raw::c_int,
    pub tm_isdst: ::std::os::raw::c_int,
    pub tm_gmtoff: ::std::os::raw::c_long,
    pub tm_zone: *mut ::std::os::raw::c_char,
}
extern "C" {
    pub static mut tzname: [*mut ::std::os::raw::c_char; 0usize];
}
extern "C" {
    pub static mut getdate_err: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut timezone: ::std::os::raw::c_long;
}
extern "C" {
    pub static mut daylight: ::std::os::raw::c_int;
}
extern "C" {
    pub fn asctime(arg1: *const tm) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn clock() -> clock_t;
}
extern "C" {
    pub fn ctime(arg1: *const time_t) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn difftime(arg1: time_t, arg2: time_t) -> f64;
}
extern "C" {
    pub fn getdate(arg1: *const ::std::os::raw::c_char) -> *mut tm;
}
extern "C" {
    pub fn gmtime(arg1: *const time_t) -> *mut tm;
}
extern "C" {
    pub fn localtime(arg1: *const time_t) -> *mut tm;
}
extern "C" {
    pub fn mktime(arg1: *mut tm) -> time_t;
}
extern "C" {
    pub fn strftime(
        arg1: *mut ::std::os::raw::c_char,
        arg2: size_t,
        arg3: *const ::std::os::raw::c_char,
        arg4: *const tm,
    ) -> size_t;
}
extern "C" {
    pub fn strptime(
        arg1: *const ::std::os::raw::c_char,
        arg2: *const ::std::os::raw::c_char,
        arg3: *mut tm,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn time(arg1: *mut time_t) -> time_t;
}
extern "C" {
    pub fn tzset();
}
extern "C" {
    pub fn asctime_r(
        arg1: *const tm,
        arg2: *mut ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn ctime_r(
        arg1: *const time_t,
        arg2: *mut ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn gmtime_r(arg1: *const time_t, arg2: *mut tm) -> *mut tm;
}
extern "C" {
    pub fn localtime_r(arg1: *const time_t, arg2: *mut tm) -> *mut tm;
}
extern "C" {
    pub fn posix2time(arg1: time_t) -> time_t;
}
extern "C" {
    pub fn tzsetwall();
}
extern "C" {
    pub fn time2posix(arg1: time_t) -> time_t;
}
extern "C" {
    pub fn timelocal(arg1: *mut tm) -> time_t;
}
extern "C" {
    pub fn timegm(arg1: *mut tm) -> time_t;
}
extern "C" {
    pub fn nanosleep(__rqtp: *const timespec, __rmtp: *mut timespec) -> ::std::os::raw::c_int;
}
pub const clockid_t__CLOCK_REALTIME: clockid_t = 0;
pub const clockid_t__CLOCK_MONOTONIC: clockid_t = 6;
pub const clockid_t__CLOCK_MONOTONIC_RAW: clockid_t = 4;
pub const clockid_t__CLOCK_MONOTONIC_RAW_APPROX: clockid_t = 5;
pub const clockid_t__CLOCK_UPTIME_RAW: clockid_t = 8;
pub const clockid_t__CLOCK_UPTIME_RAW_APPROX: clockid_t = 9;
pub const clockid_t__CLOCK_PROCESS_CPUTIME_ID: clockid_t = 12;
pub const clockid_t__CLOCK_THREAD_CPUTIME_ID: clockid_t = 16;
pub type clockid_t = u32;
extern "C" {
    pub fn clock_getres(__clock_id: clockid_t, __res: *mut timespec) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn clock_gettime(__clock_id: clockid_t, __tp: *mut timespec) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn clock_gettime_nsec_np(__clock_id: clockid_t) -> __uint64_t;
}
extern "C" {
    pub fn clock_settime(__clock_id: clockid_t, __tp: *const timespec) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn adjtime(arg1: *const timeval, arg2: *mut timeval) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn futimes(arg1: ::std::os::raw::c_int, arg2: *const timeval) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn lutimes(
        arg1: *const ::std::os::raw::c_char,
        arg2: *const timeval,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn settimeofday(arg1: *const timeval, arg2: *const timezone) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getitimer(arg1: ::std::os::raw::c_int, arg2: *mut itimerval) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn gettimeofday(
        arg1: *mut timeval,
        arg2: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_select$1050"]
    pub fn select(
        arg1: ::std::os::raw::c_int,
        arg2: *mut fd_set,
        arg3: *mut fd_set,
        arg4: *mut fd_set,
        arg5: *mut timeval,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setitimer(
        arg1: ::std::os::raw::c_int,
        arg2: *const itimerval,
        arg3: *mut itimerval,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn utimes(
        arg1: *const ::std::os::raw::c_char,
        arg2: *const timeval,
    ) -> ::std::os::raw::c_int;
}
pub type text_encoding_t = u_int32_t;
pub type fsobj_type_t = u_int32_t;
pub type fsobj_tag_t = u_int32_t;
pub type fsfile_type_t = u_int32_t;
pub type fsvolid_t = u_int32_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fsobj_id {
    pub fid_objno: u_int32_t,
    pub fid_generation: u_int32_t,
}
pub type fsobj_id_t = fsobj_id;
pub type attrgroup_t = u_int32_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct attrlist {
    pub bitmapcount: u_short,
    pub reserved: u_int16_t,
    pub commonattr: attrgroup_t,
    pub volattr: attrgroup_t,
    pub dirattr: attrgroup_t,
    pub fileattr: attrgroup_t,
    pub forkattr: attrgroup_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct attribute_set {
    pub commonattr: attrgroup_t,
    pub volattr: attrgroup_t,
    pub dirattr: attrgroup_t,
    pub fileattr: attrgroup_t,
    pub forkattr: attrgroup_t,
}
pub type attribute_set_t = attribute_set;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct attrreference {
    pub attr_dataoffset: i32,
    pub attr_length: u_int32_t,
}
pub type attrreference_t = attrreference;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct diskextent {
    pub startblock: u_int32_t,
    pub blockcount: u_int32_t,
}
pub type extentrecord = [diskextent; 8usize];
pub type vol_capabilities_set_t = [u_int32_t; 4usize];
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vol_capabilities_attr {
    pub capabilities: vol_capabilities_set_t,
    pub valid: vol_capabilities_set_t,
}
pub type vol_capabilities_attr_t = vol_capabilities_attr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vol_attributes_attr {
    pub validattr: attribute_set_t,
    pub nativeattr: attribute_set_t,
}
pub type vol_attributes_attr_t = vol_attributes_attr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fssearchblock {
    pub returnattrs: *mut attrlist,
    pub returnbuffer: *mut ::std::os::raw::c_void,
    pub returnbuffersize: size_t,
    pub maxmatches: u_long,
    pub timelimit: timeval,
    pub searchparams1: *mut ::std::os::raw::c_void,
    pub sizeofsearchparams1: size_t,
    pub searchparams2: *mut ::std::os::raw::c_void,
    pub sizeofsearchparams2: size_t,
    pub searchattrs: attrlist,
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct searchstate {
    pub ss_union_flags: u32,
    pub ss_union_layer: u32,
    pub ss_fsstate: [u_char; 548usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fsid {
    pub val: [i32; 2usize],
}
pub type fsid_t = fsid;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct statfs64 {
    pub f_bsize: u32,
    pub f_iosize: i32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: fsid_t,
    pub f_owner: uid_t,
    pub f_type: u32,
    pub f_flags: u32,
    pub f_fssubtype: u32,
    pub f_fstypename: [::std::os::raw::c_char; 16usize],
    pub f_mntonname: [::std::os::raw::c_char; 1024usize],
    pub f_mntfromname: [::std::os::raw::c_char; 1024usize],
    pub f_reserved: [u32; 8usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct statfs {
    pub f_bsize: u32,
    pub f_iosize: i32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: fsid_t,
    pub f_owner: uid_t,
    pub f_type: u32,
    pub f_flags: u32,
    pub f_fssubtype: u32,
    pub f_fstypename: [::std::os::raw::c_char; 16usize],
    pub f_mntonname: [::std::os::raw::c_char; 1024usize],
    pub f_mntfromname: [::std::os::raw::c_char; 1024usize],
    pub f_reserved: [u32; 8usize],
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub struct vfsstatfs {
    pub f_bsize: u32,
    pub f_iosize: size_t,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_bused: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: fsid_t,
    pub f_owner: uid_t,
    pub f_flags: u64,
    pub f_fstypename: [::std::os::raw::c_char; 16usize],
    pub f_mntonname: [::std::os::raw::c_char; 1024usize],
    pub f_mntfromname: [::std::os::raw::c_char; 1024usize],
    pub f_fssubtype: u32,
    pub f_reserved: [*mut ::std::os::raw::c_void; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mount {
    _unused: [u8; 0],
}
pub type mount_t = *mut mount;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vnode {
    _unused: [u8; 0],
}
pub type vnode_t = *mut vnode;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vfsconf {
    pub vfc_reserved1: u32,
    pub vfc_name: [::std::os::raw::c_char; 15usize],
    pub vfc_typenum: ::std::os::raw::c_int,
    pub vfc_refcount: ::std::os::raw::c_int,
    pub vfc_flags: ::std::os::raw::c_int,
    pub vfc_reserved2: u32,
    pub vfc_reserved3: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vfsidctl {
    pub vc_vers: ::std::os::raw::c_int,
    pub vc_fsid: fsid_t,
    pub vc_ptr: *mut ::std::os::raw::c_void,
    pub vc_len: size_t,
    pub vc_spare: [u_int32_t; 12usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vfsquery {
    pub vq_flags: u_int32_t,
    pub vq_spare: [u_int32_t; 31usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vfs_server {
    pub vs_minutes: i32,
    pub vs_server_name: [u_int8_t; 768usize],
}
#[repr(C)]
pub struct netfs_status {
    pub ns_status: u_int32_t,
    pub ns_mountopts: [::std::os::raw::c_char; 512usize],
    pub ns_waittime: u32,
    pub ns_threadcount: u32,
    pub ns_threadids: __IncompleteArrayField<u64>,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct fhandle {
    pub fh_len: ::std::os::raw::c_int,
    pub fh_data: [::std::os::raw::c_uchar; 128usize],
}
pub type fhandle_t = fhandle;
extern "C" {
    pub fn fhopen(arg1: *const fhandle, arg2: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_fstatfs$INODE64"]
    pub fn fstatfs(arg1: ::std::os::raw::c_int, arg2: *mut statfs) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fstatfs64(arg1: ::std::os::raw::c_int, arg2: *mut statfs64) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getfh(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut fhandle_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_getfsstat$INODE64"]
    pub fn getfsstat(
        arg1: *mut statfs,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getfsstat64(
        arg1: *mut statfs64,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_getmntinfo$INODE64"]
    pub fn getmntinfo(arg1: *mut *mut statfs, arg2: ::std::os::raw::c_int)
        -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_getmntinfo_r_np$INODE64"]
    pub fn getmntinfo_r_np(
        arg1: *mut *mut statfs,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getmntinfo64(
        arg1: *mut *mut statfs64,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn mount(
        arg1: *const ::std::os::raw::c_char,
        arg2: *const ::std::os::raw::c_char,
        arg3: ::std::os::raw::c_int,
        arg4: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn fmount(
        arg1: *const ::std::os::raw::c_char,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
        arg4: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[link_name = "\u{1}_statfs$INODE64"]
    pub fn statfs(arg1: *const ::std::os::raw::c_char, arg2: *mut statfs) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn statfs64(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut statfs64,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn unmount(
        arg1: *const ::std::os::raw::c_char,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getvfsbyname(
        arg1: *const ::std::os::raw::c_char,
        arg2: *mut vfsconf,
    ) -> ::std::os::raw::c_int;
}
pub type rlim_t = __uint64_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage {
    pub ru_utime: timeval,
    pub ru_stime: timeval,
    pub ru_maxrss: ::std::os::raw::c_long,
    pub ru_ixrss: ::std::os::raw::c_long,
    pub ru_idrss: ::std::os::raw::c_long,
    pub ru_isrss: ::std::os::raw::c_long,
    pub ru_minflt: ::std::os::raw::c_long,
    pub ru_majflt: ::std::os::raw::c_long,
    pub ru_nswap: ::std::os::raw::c_long,
    pub ru_inblock: ::std::os::raw::c_long,
    pub ru_oublock: ::std::os::raw::c_long,
    pub ru_msgsnd: ::std::os::raw::c_long,
    pub ru_msgrcv: ::std::os::raw::c_long,
    pub ru_nsignals: ::std::os::raw::c_long,
    pub ru_nvcsw: ::std::os::raw::c_long,
    pub ru_nivcsw: ::std::os::raw::c_long,
}
pub type rusage_info_t = *mut ::std::os::raw::c_void;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage_info_v0 {
    pub ri_uuid: [u8; 16usize],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage_info_v1 {
    pub ri_uuid: [u8; 16usize],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
    pub ri_child_user_time: u64,
    pub ri_child_system_time: u64,
    pub ri_child_pkg_idle_wkups: u64,
    pub ri_child_interrupt_wkups: u64,
    pub ri_child_pageins: u64,
    pub ri_child_elapsed_abstime: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage_info_v2 {
    pub ri_uuid: [u8; 16usize],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
    pub ri_child_user_time: u64,
    pub ri_child_system_time: u64,
    pub ri_child_pkg_idle_wkups: u64,
    pub ri_child_interrupt_wkups: u64,
    pub ri_child_pageins: u64,
    pub ri_child_elapsed_abstime: u64,
    pub ri_diskio_bytesread: u64,
    pub ri_diskio_byteswritten: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage_info_v3 {
    pub ri_uuid: [u8; 16usize],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
    pub ri_child_user_time: u64,
    pub ri_child_system_time: u64,
    pub ri_child_pkg_idle_wkups: u64,
    pub ri_child_interrupt_wkups: u64,
    pub ri_child_pageins: u64,
    pub ri_child_elapsed_abstime: u64,
    pub ri_diskio_bytesread: u64,
    pub ri_diskio_byteswritten: u64,
    pub ri_cpu_time_qos_default: u64,
    pub ri_cpu_time_qos_maintenance: u64,
    pub ri_cpu_time_qos_background: u64,
    pub ri_cpu_time_qos_utility: u64,
    pub ri_cpu_time_qos_legacy: u64,
    pub ri_cpu_time_qos_user_initiated: u64,
    pub ri_cpu_time_qos_user_interactive: u64,
    pub ri_billed_system_time: u64,
    pub ri_serviced_system_time: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rusage_info_v4 {
    pub ri_uuid: [u8; 16usize],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub ri_pkg_idle_wkups: u64,
    pub ri_interrupt_wkups: u64,
    pub ri_pageins: u64,
    pub ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub ri_proc_exit_abstime: u64,
    pub ri_child_user_time: u64,
    pub ri_child_system_time: u64,
    pub ri_child_pkg_idle_wkups: u64,
    pub ri_child_interrupt_wkups: u64,
    pub ri_child_pageins: u64,
    pub ri_child_elapsed_abstime: u64,
    pub ri_diskio_bytesread: u64,
    pub ri_diskio_byteswritten: u64,
    pub ri_cpu_time_qos_default: u64,
    pub ri_cpu_time_qos_maintenance: u64,
    pub ri_cpu_time_qos_background: u64,
    pub ri_cpu_time_qos_utility: u64,
    pub ri_cpu_time_qos_legacy: u64,
    pub ri_cpu_time_qos_user_initiated: u64,
    pub ri_cpu_time_qos_user_interactive: u64,
    pub ri_billed_system_time: u64,
    pub ri_serviced_system_time: u64,
    pub ri_logical_writes: u64,
    pub ri_lifetime_max_phys_footprint: u64,
    pub ri_instructions: u64,
    pub ri_cycles: u64,
    pub ri_billed_energy: u64,
    pub ri_serviced_energy: u64,
    pub ri_unused: [u64; 2usize],
}
pub type rusage_info_current = rusage_info_v4;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_rlimit_control_wakeupmon {
    pub wm_flags: u32,
    pub wm_rate: i32,
}
extern "C" {
    pub fn getpriority(arg1: ::std::os::raw::c_int, arg2: id_t) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getiopolicy_np(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getrlimit(arg1: ::std::os::raw::c_int, arg2: *mut rlimit) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getrusage(arg1: ::std::os::raw::c_int, arg2: *mut rusage) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setpriority(
        arg1: ::std::os::raw::c_int,
        arg2: id_t,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setiopolicy_np(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setrlimit(arg1: ::std::os::raw::c_int, arg2: *const rlimit) -> ::std::os::raw::c_int;
}
pub type sa_family_t = __uint8_t;
pub type socklen_t = __darwin_socklen_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut ::std::os::raw::c_void,
    pub iov_len: size_t,
}
pub type sae_associd_t = __uint32_t;
pub type sae_connid_t = __uint32_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sa_endpoints {
    pub sae_srcif: ::std::os::raw::c_uint,
    pub sae_srcaddr: *const sockaddr,
    pub sae_srcaddrlen: socklen_t,
    pub sae_dstaddr: *const sockaddr,
    pub sae_dstaddrlen: socklen_t,
}
pub type sa_endpoints_t = sa_endpoints;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct linger {
    pub l_onoff: ::std::os::raw::c_int,
    pub l_linger: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct so_np_extensions {
    pub npx_flags: u_int32_t,
    pub npx_mask: u_int32_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_len: __uint8_t,
    pub sa_family: sa_family_t,
    pub sa_data: [::std::os::raw::c_char; 14usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockproto {
    pub sp_family: __uint16_t,
    pub sp_protocol: __uint16_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_storage {
    pub ss_len: __uint8_t,
    pub ss_family: sa_family_t,
    pub __ss_pad1: [::std::os::raw::c_char; 6usize],
    pub __ss_align: __int64_t,
    pub __ss_pad2: [::std::os::raw::c_char; 112usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct msghdr {
    pub msg_name: *mut ::std::os::raw::c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: ::std::os::raw::c_int,
    pub msg_control: *mut ::std::os::raw::c_void,
    pub msg_controllen: socklen_t,
    pub msg_flags: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cmsghdr {
    pub cmsg_len: socklen_t,
    pub cmsg_level: ::std::os::raw::c_int,
    pub cmsg_type: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sf_hdtr {
    pub headers: *mut iovec,
    pub hdr_cnt: ::std::os::raw::c_int,
    pub trailers: *mut iovec,
    pub trl_cnt: ::std::os::raw::c_int,
}
extern "C" {
    pub fn accept(
        arg1: ::std::os::raw::c_int,
        arg2: *mut sockaddr,
        arg3: *mut socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bind(
        arg1: ::std::os::raw::c_int,
        arg2: *const sockaddr,
        arg3: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn connect(
        arg1: ::std::os::raw::c_int,
        arg2: *const sockaddr,
        arg3: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getpeername(
        arg1: ::std::os::raw::c_int,
        arg2: *mut sockaddr,
        arg3: *mut socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getsockname(
        arg1: ::std::os::raw::c_int,
        arg2: *mut sockaddr,
        arg3: *mut socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getsockopt(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
        arg4: *mut ::std::os::raw::c_void,
        arg5: *mut socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn listen(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn recv(
        arg1: ::std::os::raw::c_int,
        arg2: *mut ::std::os::raw::c_void,
        arg3: size_t,
        arg4: ::std::os::raw::c_int,
    ) -> ssize_t;
}
extern "C" {
    pub fn recvfrom(
        arg1: ::std::os::raw::c_int,
        arg2: *mut ::std::os::raw::c_void,
        arg3: size_t,
        arg4: ::std::os::raw::c_int,
        arg5: *mut sockaddr,
        arg6: *mut socklen_t,
    ) -> ssize_t;
}
extern "C" {
    pub fn recvmsg(
        arg1: ::std::os::raw::c_int,
        arg2: *mut msghdr,
        arg3: ::std::os::raw::c_int,
    ) -> ssize_t;
}
extern "C" {
    pub fn send(
        arg1: ::std::os::raw::c_int,
        arg2: *const ::std::os::raw::c_void,
        arg3: size_t,
        arg4: ::std::os::raw::c_int,
    ) -> ssize_t;
}
extern "C" {
    pub fn sendmsg(
        arg1: ::std::os::raw::c_int,
        arg2: *const msghdr,
        arg3: ::std::os::raw::c_int,
    ) -> ssize_t;
}
extern "C" {
    pub fn sendto(
        arg1: ::std::os::raw::c_int,
        arg2: *const ::std::os::raw::c_void,
        arg3: size_t,
        arg4: ::std::os::raw::c_int,
        arg5: *const sockaddr,
        arg6: socklen_t,
    ) -> ssize_t;
}
extern "C" {
    pub fn setsockopt(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
        arg4: *const ::std::os::raw::c_void,
        arg5: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn shutdown(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn sockatmark(arg1: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn socket(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn socketpair(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
        arg4: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn sendfile(
        arg1: ::std::os::raw::c_int,
        arg2: ::std::os::raw::c_int,
        arg3: off_t,
        arg4: *mut off_t,
        arg5: *mut sf_hdtr,
        arg6: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pfctlinput(arg1: ::std::os::raw::c_int, arg2: *mut sockaddr);
}
extern "C" {
    pub fn connectx(
        arg1: ::std::os::raw::c_int,
        arg2: *const sa_endpoints_t,
        arg3: sae_associd_t,
        arg4: ::std::os::raw::c_uint,
        arg5: *const iovec,
        arg6: ::std::os::raw::c_uint,
        arg7: *mut size_t,
        arg8: *mut sae_connid_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn disconnectx(
        arg1: ::std::os::raw::c_int,
        arg2: sae_associd_t,
        arg3: sae_connid_t,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_un {
    pub sun_len: ::std::os::raw::c_uchar,
    pub sun_family: sa_family_t,
    pub sun_path: [::std::os::raw::c_char; 104usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ctl_event_data {
    pub ctl_id: u_int32_t,
    pub ctl_unit: u_int32_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ctl_info {
    pub ctl_id: u_int32_t,
    pub ctl_name: [::std::os::raw::c_char; 96usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_ctl {
    pub sc_len: u_char,
    pub sc_family: u_char,
    pub ss_sysaddr: u_int16_t,
    pub sc_id: u_int32_t,
    pub sc_unit: u_int32_t,
    pub sc_reserved: [u_int32_t; 5usize],
}
#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut ::std::os::raw::c_void,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kevent64_s {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: i64,
    pub udata: u64,
    pub ext: [u64; 2usize],
}
pub const eNoteReapDeprecated: _bindgen_ty_1 = 268435456;
pub type _bindgen_ty_1 = u32;
pub const eNoteExitReparentedDeprecated: _bindgen_ty_2 = 524288;
pub type _bindgen_ty_2 = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct knote {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct klist {
    pub slh_first: *mut knote,
}
extern "C" {
    pub fn kqueue() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn kevent(
        kq: ::std::os::raw::c_int,
        changelist: *const kevent,
        nchanges: ::std::os::raw::c_int,
        eventlist: *mut kevent,
        nevents: ::std::os::raw::c_int,
        timeout: *const timespec,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn kevent64(
        kq: ::std::os::raw::c_int,
        changelist: *const kevent64_s,
        nchanges: ::std::os::raw::c_int,
        eventlist: *mut kevent64_s,
        nevents: ::std::os::raw::c_int,
        flags: ::std::os::raw::c_uint,
        timeout: *const timespec,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct net_event_data {
    pub if_family: u_int32_t,
    pub if_unit: u_int32_t,
    pub if_name: [::std::os::raw::c_char; 16usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timeval32 {
    pub tv_sec: __int32_t,
    pub tv_usec: __int32_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct if_data {
    pub ifi_type: u_char,
    pub ifi_typelen: u_char,
    pub ifi_physical: u_char,
    pub ifi_addrlen: u_char,
    pub ifi_hdrlen: u_char,
    pub ifi_recvquota: u_char,
    pub ifi_xmitquota: u_char,
    pub ifi_unused1: u_char,
    pub ifi_mtu: u_int32_t,
    pub ifi_metric: u_int32_t,
    pub ifi_baudrate: u_int32_t,
    pub ifi_ipackets: u_int32_t,
    pub ifi_ierrors: u_int32_t,
    pub ifi_opackets: u_int32_t,
    pub ifi_oerrors: u_int32_t,
    pub ifi_collisions: u_int32_t,
    pub ifi_ibytes: u_int32_t,
    pub ifi_obytes: u_int32_t,
    pub ifi_imcasts: u_int32_t,
    pub ifi_omcasts: u_int32_t,
    pub ifi_iqdrops: u_int32_t,
    pub ifi_noproto: u_int32_t,
    pub ifi_recvtiming: u_int32_t,
    pub ifi_xmittiming: u_int32_t,
    pub ifi_lastchange: timeval32,
    pub ifi_unused2: u_int32_t,
    pub ifi_hwassist: u_int32_t,
    pub ifi_reserved1: u_int32_t,
    pub ifi_reserved2: u_int32_t,
}
#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct if_data64 {
    pub ifi_type: u_char,
    pub ifi_typelen: u_char,
    pub ifi_physical: u_char,
    pub ifi_addrlen: u_char,
    pub ifi_hdrlen: u_char,
    pub ifi_recvquota: u_char,
    pub ifi_xmitquota: u_char,
    pub ifi_unused1: u_char,
    pub ifi_mtu: u_int32_t,
    pub ifi_metric: u_int32_t,
    pub ifi_baudrate: u_int64_t,
    pub ifi_ipackets: u_int64_t,
    pub ifi_ierrors: u_int64_t,
    pub ifi_opackets: u_int64_t,
    pub ifi_oerrors: u_int64_t,
    pub ifi_collisions: u_int64_t,
    pub ifi_ibytes: u_int64_t,
    pub ifi_obytes: u_int64_t,
    pub ifi_imcasts: u_int64_t,
    pub ifi_omcasts: u_int64_t,
    pub ifi_iqdrops: u_int64_t,
    pub ifi_noproto: u_int64_t,
    pub ifi_recvtiming: u_int32_t,
    pub ifi_xmittiming: u_int32_t,
    pub ifi_lastchange: timeval32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifqueue {
    pub ifq_head: *mut ::std::os::raw::c_void,
    pub ifq_tail: *mut ::std::os::raw::c_void,
    pub ifq_len: ::std::os::raw::c_int,
    pub ifq_maxlen: ::std::os::raw::c_int,
    pub ifq_drops: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct if_clonereq {
    pub ifcr_total: ::std::os::raw::c_int,
    pub ifcr_count: ::std::os::raw::c_int,
    pub ifcr_buffer: *mut ::std::os::raw::c_char,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct if_msghdr {
    pub ifm_msglen: ::std::os::raw::c_ushort,
    pub ifm_version: ::std::os::raw::c_uchar,
    pub ifm_type: ::std::os::raw::c_uchar,
    pub ifm_addrs: ::std::os::raw::c_int,
    pub ifm_flags: ::std::os::raw::c_int,
    pub ifm_index: ::std::os::raw::c_ushort,
    pub ifm_data: if_data,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifa_msghdr {
    pub ifam_msglen: ::std::os::raw::c_ushort,
    pub ifam_version: ::std::os::raw::c_uchar,
    pub ifam_type: ::std::os::raw::c_uchar,
    pub ifam_addrs: ::std::os::raw::c_int,
    pub ifam_flags: ::std::os::raw::c_int,
    pub ifam_index: ::std::os::raw::c_ushort,
    pub ifam_metric: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifma_msghdr {
    pub ifmam_msglen: ::std::os::raw::c_ushort,
    pub ifmam_version: ::std::os::raw::c_uchar,
    pub ifmam_type: ::std::os::raw::c_uchar,
    pub ifmam_addrs: ::std::os::raw::c_int,
    pub ifmam_flags: ::std::os::raw::c_int,
    pub ifmam_index: ::std::os::raw::c_ushort,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct if_msghdr2 {
    pub ifm_msglen: u_short,
    pub ifm_version: u_char,
    pub ifm_type: u_char,
    pub ifm_addrs: ::std::os::raw::c_int,
    pub ifm_flags: ::std::os::raw::c_int,
    pub ifm_index: u_short,
    pub ifm_snd_len: ::std::os::raw::c_int,
    pub ifm_snd_maxlen: ::std::os::raw::c_int,
    pub ifm_snd_drops: ::std::os::raw::c_int,
    pub ifm_timer: ::std::os::raw::c_int,
    pub ifm_data: if_data64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifma_msghdr2 {
    pub ifmam_msglen: u_short,
    pub ifmam_version: u_char,
    pub ifmam_type: u_char,
    pub ifmam_addrs: ::std::os::raw::c_int,
    pub ifmam_flags: ::std::os::raw::c_int,
    pub ifmam_index: u_short,
    pub ifmam_refcount: i32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifdevmtu {
    pub ifdm_current: ::std::os::raw::c_int,
    pub ifdm_min: ::std::os::raw::c_int,
    pub ifdm_max: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifkpi {
    pub ifk_module_id: ::std::os::raw::c_uint,
    pub ifk_type: ::std::os::raw::c_uint,
    pub ifk_data: ifkpi__bindgen_ty_1,
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub union ifkpi__bindgen_ty_1 {
    pub ifk_ptr: *mut ::std::os::raw::c_void,
    pub ifk_value: ::std::os::raw::c_int,
    _bindgen_union_align: [u32; 2usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_name: [::std::os::raw::c_char; 16usize],
    pub ifr_ifru: ifreq__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union ifreq__bindgen_ty_1 {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_flags: ::std::os::raw::c_short,
    pub ifru_metric: ::std::os::raw::c_int,
    pub ifru_mtu: ::std::os::raw::c_int,
    pub ifru_phys: ::std::os::raw::c_int,
    pub ifru_media: ::std::os::raw::c_int,
    pub ifru_intval: ::std::os::raw::c_int,
    pub ifru_data: caddr_t,
    pub ifru_devmtu: ifdevmtu,
    pub ifru_kpi: ifkpi,
    pub ifru_wake_flags: u_int32_t,
    pub ifru_route_refcnt: u_int32_t,
    pub ifru_cap: [::std::os::raw::c_int; 2usize],
    pub ifru_functional_type: u_int32_t,
    _bindgen_union_align: [u64; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ifaliasreq {
    pub ifra_name: [::std::os::raw::c_char; 16usize],
    pub ifra_addr: sockaddr,
    pub ifra_broadaddr: sockaddr,
    pub ifra_mask: sockaddr,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rslvmulti_req {
    pub sa: *mut sockaddr,
    pub llsa: *mut *mut sockaddr,
}
#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct ifmediareq {
    pub ifm_name: [::std::os::raw::c_char; 16usize],
    pub ifm_current: ::std::os::raw::c_int,
    pub ifm_mask: ::std::os::raw::c_int,
    pub ifm_status: ::std::os::raw::c_int,
    pub ifm_active: ::std::os::raw::c_int,
    pub ifm_count: ::std::os::raw::c_int,
    pub ifm_ulist: *mut ::std::os::raw::c_int,
}
#[repr(C, packed(4))]
#[derive(Debug, Copy, Clone)]
pub struct ifdrv {
    pub ifd_name: [::std::os::raw::c_char; 16usize],
    pub ifd_cmd: ::std::os::raw::c_ulong,
    pub ifd_len: size_t,
    pub ifd_data: *mut ::std::os::raw::c_void,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifstat {
    pub ifs_name: [::std::os::raw::c_char; 16usize],
    pub ascii: [::std::os::raw::c_char; 801usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifconf {
    pub ifc_len: ::std::os::raw::c_int,
    pub ifc_ifcu: ifconf__bindgen_ty_1,
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub union ifconf__bindgen_ty_1 {
    pub ifcu_buf: caddr_t,
    pub ifcu_req: *mut ifreq,
    _bindgen_union_align: [u32; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kev_dl_proto_data {
    pub link_data: net_event_data,
    pub proto_family: u_int32_t,
    pub proto_remaining_count: u_int32_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct if_nameindex {
    pub if_index: ::std::os::raw::c_uint,
    pub if_name: *mut ::std::os::raw::c_char,
}
extern "C" {
    pub fn if_nametoindex(arg1: *const ::std::os::raw::c_char) -> ::std::os::raw::c_uint;
}
extern "C" {
    pub fn if_indextoname(
        arg1: ::std::os::raw::c_uint,
        arg2: *mut ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn if_nameindex() -> *mut if_nameindex;
}
extern "C" {
    pub fn if_freenameindex(arg1: *mut if_nameindex);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_metrics {
    pub rmx_locks: u_int32_t,
    pub rmx_mtu: u_int32_t,
    pub rmx_hopcount: u_int32_t,
    pub rmx_expire: i32,
    pub rmx_recvpipe: u_int32_t,
    pub rmx_sendpipe: u_int32_t,
    pub rmx_ssthresh: u_int32_t,
    pub rmx_rtt: u_int32_t,
    pub rmx_rttvar: u_int32_t,
    pub rmx_pksent: u_int32_t,
    pub rmx_state: u_int32_t,
    pub rmx_filler: [u_int32_t; 3usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtstat {
    pub rts_badredirect: ::std::os::raw::c_short,
    pub rts_dynamic: ::std::os::raw::c_short,
    pub rts_newgateway: ::std::os::raw::c_short,
    pub rts_unreach: ::std::os::raw::c_short,
    pub rts_wildcard: ::std::os::raw::c_short,
    pub rts_badrtgwroute: ::std::os::raw::c_short,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_msghdr {
    pub rtm_msglen: u_short,
    pub rtm_version: u_char,
    pub rtm_type: u_char,
    pub rtm_index: u_short,
    pub rtm_flags: ::std::os::raw::c_int,
    pub rtm_addrs: ::std::os::raw::c_int,
    pub rtm_pid: pid_t,
    pub rtm_seq: ::std::os::raw::c_int,
    pub rtm_errno: ::std::os::raw::c_int,
    pub rtm_use: ::std::os::raw::c_int,
    pub rtm_inits: u_int32_t,
    pub rtm_rmx: rt_metrics,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_msghdr2 {
    pub rtm_msglen: u_short,
    pub rtm_version: u_char,
    pub rtm_type: u_char,
    pub rtm_index: u_short,
    pub rtm_flags: ::std::os::raw::c_int,
    pub rtm_addrs: ::std::os::raw::c_int,
    pub rtm_refcnt: i32,
    pub rtm_parentflags: ::std::os::raw::c_int,
    pub rtm_reserved: ::std::os::raw::c_int,
    pub rtm_use: ::std::os::raw::c_int,
    pub rtm_inits: u_int32_t,
    pub rtm_rmx: rt_metrics,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_addrinfo {
    pub rti_addrs: ::std::os::raw::c_int,
    pub rti_info: [*mut sockaddr; 8usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub sin_len: __uint8_t,
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [::std::os::raw::c_char; 8usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip_opts {
    pub ip_dst: in_addr,
    pub ip_opts: [::std::os::raw::c_char; 40usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ip_mreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ip_mreqn {
    pub imr_multiaddr: in_addr,
    pub imr_address: in_addr,
    pub imr_ifindex: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ip_mreq_source {
    pub imr_multiaddr: in_addr,
    pub imr_sourceaddr: in_addr,
    pub imr_interface: in_addr,
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub struct group_req {
    pub gr_interface: u32,
    pub gr_group: sockaddr_storage,
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub struct group_source_req {
    pub gsr_interface: u32,
    pub gsr_group: sockaddr_storage,
    pub gsr_source: sockaddr_storage,
}
#[repr(C, packed(4))]
#[derive(Copy, Clone)]
pub struct __msfilterreq {
    pub msfr_ifindex: u32,
    pub msfr_fmode: u32,
    pub msfr_nsrcs: u32,
    pub __msfr_align: u32,
    pub msfr_group: sockaddr_storage,
    pub msfr_srcs: *mut sockaddr_storage,
}
extern "C" {
    pub fn setipv4sourcefilter(
        arg1: ::std::os::raw::c_int,
        arg2: in_addr,
        arg3: in_addr,
        arg4: u32,
        arg5: u32,
        arg6: *mut in_addr,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getipv4sourcefilter(
        arg1: ::std::os::raw::c_int,
        arg2: in_addr,
        arg3: in_addr,
        arg4: *mut u32,
        arg5: *mut u32,
        arg6: *mut in_addr,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn setsourcefilter(
        arg1: ::std::os::raw::c_int,
        arg2: u32,
        arg3: *mut sockaddr,
        arg4: socklen_t,
        arg5: u32,
        arg6: u32,
        arg7: *mut sockaddr_storage,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn getsourcefilter(
        arg1: ::std::os::raw::c_int,
        arg2: u32,
        arg3: *mut sockaddr,
        arg4: socklen_t,
        arg5: *mut u32,
        arg6: *mut u32,
        arg7: *mut sockaddr_storage,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_pktinfo {
    pub ipi_ifindex: ::std::os::raw::c_uint,
    pub ipi_spec_dst: in_addr,
    pub ipi_addr: in_addr,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub __u6_addr: in6_addr__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union in6_addr__bindgen_ty_1 {
    pub __u6_addr8: [__uint8_t; 16usize],
    pub __u6_addr16: [__uint16_t; 8usize],
    pub __u6_addr32: [__uint32_t; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_len: __uint8_t,
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: __uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: __uint32_t,
}
extern "C" {
    pub static in6addr_any: in6_addr;
}
extern "C" {
    pub static in6addr_loopback: in6_addr;
}
extern "C" {
    pub static in6addr_nodelocal_allnodes: in6_addr;
}
extern "C" {
    pub static in6addr_linklocal_allnodes: in6_addr;
}
extern "C" {
    pub static in6addr_linklocal_allrouters: in6_addr;
}
extern "C" {
    pub static in6addr_linklocal_allv2routers: in6_addr;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ipv6_mreq {
    pub ipv6mr_multiaddr: in6_addr,
    pub ipv6mr_interface: ::std::os::raw::c_uint,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_pktinfo {
    pub ipi6_addr: in6_addr,
    pub ipi6_ifindex: ::std::os::raw::c_uint,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_mtuinfo {
    pub ip6m_addr: sockaddr_in6,
    pub ip6m_mtu: u32,
}
extern "C" {
    pub fn inet6_option_space(arg1: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_option_init(
        arg1: *mut ::std::os::raw::c_void,
        arg2: *mut *mut cmsghdr,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_option_append(
        arg1: *mut cmsghdr,
        arg2: *const __uint8_t,
        arg3: ::std::os::raw::c_int,
        arg4: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_option_alloc(
        arg1: *mut cmsghdr,
        arg2: ::std::os::raw::c_int,
        arg3: ::std::os::raw::c_int,
        arg4: ::std::os::raw::c_int,
    ) -> *mut __uint8_t;
}
extern "C" {
    pub fn inet6_option_next(
        arg1: *const cmsghdr,
        arg2: *mut *mut __uint8_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_option_find(
        arg1: *const cmsghdr,
        arg2: *mut *mut __uint8_t,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rthdr_space(arg1: ::std::os::raw::c_int, arg2: ::std::os::raw::c_int) -> size_t;
}
extern "C" {
    pub fn inet6_rthdr_init(
        arg1: *mut ::std::os::raw::c_void,
        arg2: ::std::os::raw::c_int,
    ) -> *mut cmsghdr;
}
extern "C" {
    pub fn inet6_rthdr_add(
        arg1: *mut cmsghdr,
        arg2: *const in6_addr,
        arg3: ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rthdr_lasthop(
        arg1: *mut cmsghdr,
        arg2: ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rthdr_segments(arg1: *const cmsghdr) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rthdr_getaddr(arg1: *mut cmsghdr, arg2: ::std::os::raw::c_int) -> *mut in6_addr;
}
extern "C" {
    pub fn inet6_rthdr_getflags(
        arg1: *const cmsghdr,
        arg2: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_init(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_append(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
        arg3: ::std::os::raw::c_int,
        arg4: __uint8_t,
        arg5: socklen_t,
        arg6: __uint8_t,
        arg7: *mut *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_finish(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
        arg3: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_set_val(
        arg1: *mut ::std::os::raw::c_void,
        arg2: ::std::os::raw::c_int,
        arg3: *mut ::std::os::raw::c_void,
        arg4: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_next(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
        arg3: ::std::os::raw::c_int,
        arg4: *mut __uint8_t,
        arg5: *mut socklen_t,
        arg6: *mut *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_find(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
        arg3: ::std::os::raw::c_int,
        arg4: __uint8_t,
        arg5: *mut socklen_t,
        arg6: *mut *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_opt_get_val(
        arg1: *mut ::std::os::raw::c_void,
        arg2: ::std::os::raw::c_int,
        arg3: *mut ::std::os::raw::c_void,
        arg4: socklen_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rth_space(arg1: ::std::os::raw::c_int, arg2: ::std::os::raw::c_int) -> socklen_t;
}
extern "C" {
    pub fn inet6_rth_init(
        arg1: *mut ::std::os::raw::c_void,
        arg2: socklen_t,
        arg3: ::std::os::raw::c_int,
        arg4: ::std::os::raw::c_int,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn inet6_rth_add(
        arg1: *mut ::std::os::raw::c_void,
        arg2: *const in6_addr,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rth_reverse(
        arg1: *const ::std::os::raw::c_void,
        arg2: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rth_segments(arg1: *const ::std::os::raw::c_void) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn inet6_rth_getaddr(
        arg1: *const ::std::os::raw::c_void,
        arg2: ::std::os::raw::c_int,
    ) -> *mut in6_addr;
}
extern "C" {
    pub fn addrsel_policy_init();
}
extern "C" {
    pub fn bindresvport(
        arg1: ::std::os::raw::c_int,
        arg2: *mut sockaddr_in,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bindresvport_sa(
        arg1: ::std::os::raw::c_int,
        arg2: *mut sockaddr,
    ) -> ::std::os::raw::c_int;
}
pub type tcp_seq = __uint32_t;
pub type tcp_cc = __uint32_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcphdr {
    pub th_sport: ::std::os::raw::c_ushort,
    pub th_dport: ::std::os::raw::c_ushort,
    pub th_seq: tcp_seq,
    pub th_ack: tcp_seq,
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize], u8>,
    pub th_flags: ::std::os::raw::c_uchar,
    pub th_win: ::std::os::raw::c_ushort,
    pub th_sum: ::std::os::raw::c_ushort,
    pub th_urp: ::std::os::raw::c_ushort,
}
impl tcphdr {
    #[inline]
    pub fn th_x2(&self) -> ::std::os::raw::c_uint {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u32) }
    }
    #[inline]
    pub fn set_th_x2(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn th_off(&self) -> ::std::os::raw::c_uint {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u32) }
    }
    #[inline]
    pub fn set_th_off(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        th_x2: ::std::os::raw::c_uint,
        th_off: ::std::os::raw::c_uint,
    ) -> __BindgenBitfieldUnit<[u8; 1usize], u8> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize], u8> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let th_x2: u32 = unsafe { ::std::mem::transmute(th_x2) };
            th_x2 as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let th_off: u32 = unsafe { ::std::mem::transmute(th_off) };
            th_off as u64
        });
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcp_connection_info {
    pub tcpi_state: u_int8_t,
    pub tcpi_snd_wscale: u_int8_t,
    pub tcpi_rcv_wscale: u_int8_t,
    pub __pad1: u_int8_t,
    pub tcpi_options: u_int32_t,
    pub tcpi_flags: u_int32_t,
    pub tcpi_rto: u_int32_t,
    pub tcpi_maxseg: u_int32_t,
    pub tcpi_snd_ssthresh: u_int32_t,
    pub tcpi_snd_cwnd: u_int32_t,
    pub tcpi_snd_wnd: u_int32_t,
    pub tcpi_snd_sbbytes: u_int32_t,
    pub tcpi_rcv_wnd: u_int32_t,
    pub tcpi_rttcur: u_int32_t,
    pub tcpi_srtt: u_int32_t,
    pub tcpi_rttvar: u_int32_t,
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize], u32>,
    pub tcpi_txpackets: u_int64_t,
    pub tcpi_txbytes: u_int64_t,
    pub tcpi_txretransmitbytes: u_int64_t,
    pub tcpi_rxpackets: u_int64_t,
    pub tcpi_rxbytes: u_int64_t,
    pub tcpi_rxoutoforderbytes: u_int64_t,
    pub tcpi_txretransmitpackets: u_int64_t,
}
impl tcp_connection_info {
    #[inline]
    pub fn tcpi_tfo_cookie_req(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_req(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_cookie_rcv(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(1usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_rcv(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(1usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_syn_loss(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(2usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_syn_loss(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(2usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_syn_data_sent(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(3usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_syn_data_sent(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(3usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_syn_data_acked(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_syn_data_acked(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_syn_data_rcv(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(5usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_syn_data_rcv(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(5usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_cookie_req_rcv(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(6usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_req_rcv(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(6usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_cookie_sent(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(7usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_sent(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(7usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_cookie_invalid(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(8usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_invalid(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(8usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_cookie_wrong(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(9usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_cookie_wrong(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(9usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_no_cookie_rcv(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(10usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_no_cookie_rcv(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(10usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_heuristics_disable(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(11usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_heuristics_disable(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(11usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_send_blackhole(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(12usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_send_blackhole(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(12usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_recv_blackhole(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(13usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_recv_blackhole(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(13usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tcpi_tfo_onebyte_proxy(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(14usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_tcpi_tfo_onebyte_proxy(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(14usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn __pad2(&self) -> u_int32_t {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(15usize, 17u8) as u32) }
    }
    #[inline]
    pub fn set___pad2(&mut self, val: u_int32_t) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(15usize, 17u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        tcpi_tfo_cookie_req: u_int32_t,
        tcpi_tfo_cookie_rcv: u_int32_t,
        tcpi_tfo_syn_loss: u_int32_t,
        tcpi_tfo_syn_data_sent: u_int32_t,
        tcpi_tfo_syn_data_acked: u_int32_t,
        tcpi_tfo_syn_data_rcv: u_int32_t,
        tcpi_tfo_cookie_req_rcv: u_int32_t,
        tcpi_tfo_cookie_sent: u_int32_t,
        tcpi_tfo_cookie_invalid: u_int32_t,
        tcpi_tfo_cookie_wrong: u_int32_t,
        tcpi_tfo_no_cookie_rcv: u_int32_t,
        tcpi_tfo_heuristics_disable: u_int32_t,
        tcpi_tfo_send_blackhole: u_int32_t,
        tcpi_tfo_recv_blackhole: u_int32_t,
        tcpi_tfo_onebyte_proxy: u_int32_t,
        __pad2: u_int32_t,
    ) -> __BindgenBitfieldUnit<[u8; 4usize], u32> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 4usize], u32> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let tcpi_tfo_cookie_req: u32 = unsafe { ::std::mem::transmute(tcpi_tfo_cookie_req) };
            tcpi_tfo_cookie_req as u64
        });
        __bindgen_bitfield_unit.set(1usize, 1u8, {
            let tcpi_tfo_cookie_rcv: u32 = unsafe { ::std::mem::transmute(tcpi_tfo_cookie_rcv) };
            tcpi_tfo_cookie_rcv as u64
        });
        __bindgen_bitfield_unit.set(2usize, 1u8, {
            let tcpi_tfo_syn_loss: u32 = unsafe { ::std::mem::transmute(tcpi_tfo_syn_loss) };
            tcpi_tfo_syn_loss as u64
        });
        __bindgen_bitfield_unit.set(3usize, 1u8, {
            let tcpi_tfo_syn_data_sent: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_syn_data_sent) };
            tcpi_tfo_syn_data_sent as u64
        });
        __bindgen_bitfield_unit.set(4usize, 1u8, {
            let tcpi_tfo_syn_data_acked: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_syn_data_acked) };
            tcpi_tfo_syn_data_acked as u64
        });
        __bindgen_bitfield_unit.set(5usize, 1u8, {
            let tcpi_tfo_syn_data_rcv: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_syn_data_rcv) };
            tcpi_tfo_syn_data_rcv as u64
        });
        __bindgen_bitfield_unit.set(6usize, 1u8, {
            let tcpi_tfo_cookie_req_rcv: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_cookie_req_rcv) };
            tcpi_tfo_cookie_req_rcv as u64
        });
        __bindgen_bitfield_unit.set(7usize, 1u8, {
            let tcpi_tfo_cookie_sent: u32 = unsafe { ::std::mem::transmute(tcpi_tfo_cookie_sent) };
            tcpi_tfo_cookie_sent as u64
        });
        __bindgen_bitfield_unit.set(8usize, 1u8, {
            let tcpi_tfo_cookie_invalid: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_cookie_invalid) };
            tcpi_tfo_cookie_invalid as u64
        });
        __bindgen_bitfield_unit.set(9usize, 1u8, {
            let tcpi_tfo_cookie_wrong: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_cookie_wrong) };
            tcpi_tfo_cookie_wrong as u64
        });
        __bindgen_bitfield_unit.set(10usize, 1u8, {
            let tcpi_tfo_no_cookie_rcv: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_no_cookie_rcv) };
            tcpi_tfo_no_cookie_rcv as u64
        });
        __bindgen_bitfield_unit.set(11usize, 1u8, {
            let tcpi_tfo_heuristics_disable: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_heuristics_disable) };
            tcpi_tfo_heuristics_disable as u64
        });
        __bindgen_bitfield_unit.set(12usize, 1u8, {
            let tcpi_tfo_send_blackhole: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_send_blackhole) };
            tcpi_tfo_send_blackhole as u64
        });
        __bindgen_bitfield_unit.set(13usize, 1u8, {
            let tcpi_tfo_recv_blackhole: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_recv_blackhole) };
            tcpi_tfo_recv_blackhole as u64
        });
        __bindgen_bitfield_unit.set(14usize, 1u8, {
            let tcpi_tfo_onebyte_proxy: u32 =
                unsafe { ::std::mem::transmute(tcpi_tfo_onebyte_proxy) };
            tcpi_tfo_onebyte_proxy as u64
        });
        __bindgen_bitfield_unit.set(15usize, 17u8, {
            let __pad2: u32 = unsafe { ::std::mem::transmute(__pad2) };
            __pad2 as u64
        });
        __bindgen_bitfield_unit
    }
}
pub type cpu_type_t = integer_t;
pub type cpu_subtype_t = integer_t;
pub type cpu_threadtype_t = integer_t;
pub type uuid_t = __darwin_uuid_t;
pub type uuid_string_t = __darwin_uuid_string_t;
extern "C" {
    pub static UUID_NULL: uuid_t;
}
extern "C" {
    pub fn uuid_clear(uu: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn uuid_compare(
        uu1: *mut ::std::os::raw::c_uchar,
        uu2: *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn uuid_copy(dst: *mut ::std::os::raw::c_uchar, src: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn uuid_generate(out: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn uuid_generate_random(out: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn uuid_generate_time(out: *mut ::std::os::raw::c_uchar);
}
extern "C" {
    pub fn uuid_is_null(uu: *mut ::std::os::raw::c_uchar) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn uuid_parse(
        in_: *mut ::std::os::raw::c_char,
        uu: *mut ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn uuid_unparse(uu: *mut ::std::os::raw::c_uchar, out: *mut ::std::os::raw::c_char);
}
extern "C" {
    pub fn uuid_unparse_lower(uu: *mut ::std::os::raw::c_uchar, out: *mut ::std::os::raw::c_char);
}
extern "C" {
    pub fn uuid_unparse_upper(uu: *mut ::std::os::raw::c_uchar, out: *mut ::std::os::raw::c_char);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_bsdinfo {
    pub pbi_flags: u32,
    pub pbi_status: u32,
    pub pbi_xstatus: u32,
    pub pbi_pid: u32,
    pub pbi_ppid: u32,
    pub pbi_uid: uid_t,
    pub pbi_gid: gid_t,
    pub pbi_ruid: uid_t,
    pub pbi_rgid: gid_t,
    pub pbi_svuid: uid_t,
    pub pbi_svgid: gid_t,
    pub rfu_1: u32,
    pub pbi_comm: [::std::os::raw::c_char; 16usize],
    pub pbi_name: [::std::os::raw::c_char; 32usize],
    pub pbi_nfiles: u32,
    pub pbi_pgid: u32,
    pub pbi_pjobc: u32,
    pub e_tdev: u32,
    pub e_tpgid: u32,
    pub pbi_nice: i32,
    pub pbi_start_tvsec: u64,
    pub pbi_start_tvusec: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_bsdshortinfo {
    pub pbsi_pid: u32,
    pub pbsi_ppid: u32,
    pub pbsi_pgid: u32,
    pub pbsi_status: u32,
    pub pbsi_comm: [::std::os::raw::c_char; 16usize],
    pub pbsi_flags: u32,
    pub pbsi_uid: uid_t,
    pub pbsi_gid: gid_t,
    pub pbsi_ruid: uid_t,
    pub pbsi_rgid: gid_t,
    pub pbsi_svuid: uid_t,
    pub pbsi_svgid: gid_t,
    pub pbsi_rfu: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_taskinfo {
    pub pti_virtual_size: u64,
    pub pti_resident_size: u64,
    pub pti_total_user: u64,
    pub pti_total_system: u64,
    pub pti_threads_user: u64,
    pub pti_threads_system: u64,
    pub pti_policy: i32,
    pub pti_faults: i32,
    pub pti_pageins: i32,
    pub pti_cow_faults: i32,
    pub pti_messages_sent: i32,
    pub pti_messages_received: i32,
    pub pti_syscalls_mach: i32,
    pub pti_syscalls_unix: i32,
    pub pti_csw: i32,
    pub pti_threadnum: i32,
    pub pti_numrunning: i32,
    pub pti_priority: i32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_taskallinfo {
    pub pbsd: proc_bsdinfo,
    pub ptinfo: proc_taskinfo,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_threadinfo {
    pub pth_user_time: u64,
    pub pth_system_time: u64,
    pub pth_cpu_usage: i32,
    pub pth_policy: i32,
    pub pth_run_state: i32,
    pub pth_flags: i32,
    pub pth_sleep_time: i32,
    pub pth_curpri: i32,
    pub pth_priority: i32,
    pub pth_maxpriority: i32,
    pub pth_name: [::std::os::raw::c_char; 64usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_regioninfo {
    pub pri_protection: u32,
    pub pri_max_protection: u32,
    pub pri_inheritance: u32,
    pub pri_flags: u32,
    pub pri_offset: u64,
    pub pri_behavior: u32,
    pub pri_user_wired_count: u32,
    pub pri_user_tag: u32,
    pub pri_pages_resident: u32,
    pub pri_pages_shared_now_private: u32,
    pub pri_pages_swapped_out: u32,
    pub pri_pages_dirtied: u32,
    pub pri_ref_count: u32,
    pub pri_shadow_depth: u32,
    pub pri_share_mode: u32,
    pub pri_private_pages_resident: u32,
    pub pri_shared_pages_resident: u32,
    pub pri_obj_id: u32,
    pub pri_depth: u32,
    pub pri_address: u64,
    pub pri_size: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_workqueueinfo {
    pub pwq_nthreads: u32,
    pub pwq_runthreads: u32,
    pub pwq_blockedthreads: u32,
    pub pwq_state: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_fileinfo {
    pub fi_openflags: u32,
    pub fi_status: u32,
    pub fi_offset: off_t,
    pub fi_type: i32,
    pub fi_guardflags: u32,
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct proc_exitreasonbasicinfo {
    pub beri_namespace: u32,
    pub beri_code: u64,
    pub beri_flags: u64,
    pub beri_reason_buf_size: u32,
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct proc_exitreasoninfo {
    pub eri_namespace: u32,
    pub eri_code: u64,
    pub eri_flags: u64,
    pub eri_reason_buf_size: u32,
    pub eri_kcd_buf: u64,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vinfo_stat {
    pub vst_dev: u32,
    pub vst_mode: u16,
    pub vst_nlink: u16,
    pub vst_ino: u64,
    pub vst_uid: uid_t,
    pub vst_gid: gid_t,
    pub vst_atime: i64,
    pub vst_atimensec: i64,
    pub vst_mtime: i64,
    pub vst_mtimensec: i64,
    pub vst_ctime: i64,
    pub vst_ctimensec: i64,
    pub vst_birthtime: i64,
    pub vst_birthtimensec: i64,
    pub vst_size: off_t,
    pub vst_blocks: i64,
    pub vst_blksize: i32,
    pub vst_flags: u32,
    pub vst_gen: u32,
    pub vst_rdev: u32,
    pub vst_qspare: [i64; 2usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vnode_info {
    pub vi_stat: vinfo_stat,
    pub vi_type: ::std::os::raw::c_int,
    pub vi_pad: ::std::os::raw::c_int,
    pub vi_fsid: fsid_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vnode_info_path {
    pub vip_vi: vnode_info,
    pub vip_path: [::std::os::raw::c_char; 1024usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vnode_fdinfo {
    pub pfi: proc_fileinfo,
    pub pvi: vnode_info,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vnode_fdinfowithpath {
    pub pfi: proc_fileinfo,
    pub pvip: vnode_info_path,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_regionwithpathinfo {
    pub prp_prinfo: proc_regioninfo,
    pub prp_vip: vnode_info_path,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_vnodepathinfo {
    pub pvi_cdir: vnode_info_path,
    pub pvi_rdir: vnode_info_path,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_threadwithpathinfo {
    pub pt: proc_threadinfo,
    pub pvip: vnode_info_path,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in4in6_addr {
    pub i46a_pad32: [u_int32_t; 3usize],
    pub i46a_addr4: in_addr,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_sockinfo {
    pub insi_fport: ::std::os::raw::c_int,
    pub insi_lport: ::std::os::raw::c_int,
    pub insi_gencnt: u64,
    pub insi_flags: u32,
    pub insi_flow: u32,
    pub insi_vflag: u8,
    pub insi_ip_ttl: u8,
    pub rfu_1: u32,
    pub insi_faddr: in_sockinfo__bindgen_ty_1,
    pub insi_laddr: in_sockinfo__bindgen_ty_2,
    pub insi_v4: in_sockinfo__bindgen_ty_3,
    pub insi_v6: in_sockinfo__bindgen_ty_4,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union in_sockinfo__bindgen_ty_1 {
    pub ina_46: in4in6_addr,
    pub ina_6: in6_addr,
    _bindgen_union_align: [u32; 4usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union in_sockinfo__bindgen_ty_2 {
    pub ina_46: in4in6_addr,
    pub ina_6: in6_addr,
    _bindgen_union_align: [u32; 4usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_sockinfo__bindgen_ty_3 {
    pub in4_tos: u_char,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_sockinfo__bindgen_ty_4 {
    pub in6_hlim: u8,
    pub in6_cksum: ::std::os::raw::c_int,
    pub in6_ifindex: u_short,
    pub in6_hops: ::std::os::raw::c_short,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_sockinfo {
    pub tcpsi_ini: in_sockinfo,
    pub tcpsi_state: ::std::os::raw::c_int,
    pub tcpsi_timer: [::std::os::raw::c_int; 4usize],
    pub tcpsi_mss: ::std::os::raw::c_int,
    pub tcpsi_flags: u32,
    pub rfu_1: u32,
    pub tcpsi_tp: u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct un_sockinfo {
    pub unsi_conn_so: u64,
    pub unsi_conn_pcb: u64,
    pub unsi_addr: un_sockinfo__bindgen_ty_1,
    pub unsi_caddr: un_sockinfo__bindgen_ty_2,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union un_sockinfo__bindgen_ty_1 {
    pub ua_sun: sockaddr_un,
    pub ua_dummy: [::std::os::raw::c_char; 255usize],
    _bindgen_union_align: [u8; 255usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union un_sockinfo__bindgen_ty_2 {
    pub ua_sun: sockaddr_un,
    pub ua_dummy: [::std::os::raw::c_char; 255usize],
    _bindgen_union_align: [u8; 255usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ndrv_info {
    pub ndrvsi_if_family: u32,
    pub ndrvsi_if_unit: u32,
    pub ndrvsi_if_name: [::std::os::raw::c_char; 16usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kern_event_info {
    pub kesi_vendor_code_filter: u32,
    pub kesi_class_filter: u32,
    pub kesi_subclass_filter: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kern_ctl_info {
    pub kcsi_id: u32,
    pub kcsi_reg_unit: u32,
    pub kcsi_flags: u32,
    pub kcsi_recvbufsize: u32,
    pub kcsi_sendbufsize: u32,
    pub kcsi_unit: u32,
    pub kcsi_name: [::std::os::raw::c_char; 96usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockbuf_info {
    pub sbi_cc: u32,
    pub sbi_hiwat: u32,
    pub sbi_mbcnt: u32,
    pub sbi_mbmax: u32,
    pub sbi_lowat: u32,
    pub sbi_flags: ::std::os::raw::c_short,
    pub sbi_timeo: ::std::os::raw::c_short,
}
pub const SOCKINFO_GENERIC: _bindgen_ty_3 = 0;
pub const SOCKINFO_IN: _bindgen_ty_3 = 1;
pub const SOCKINFO_TCP: _bindgen_ty_3 = 2;
pub const SOCKINFO_UN: _bindgen_ty_3 = 3;
pub const SOCKINFO_NDRV: _bindgen_ty_3 = 4;
pub const SOCKINFO_KERN_EVENT: _bindgen_ty_3 = 5;
pub const SOCKINFO_KERN_CTL: _bindgen_ty_3 = 6;
pub type _bindgen_ty_3 = u32;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct socket_info {
    pub soi_stat: vinfo_stat,
    pub soi_so: u64,
    pub soi_pcb: u64,
    pub soi_type: ::std::os::raw::c_int,
    pub soi_protocol: ::std::os::raw::c_int,
    pub soi_family: ::std::os::raw::c_int,
    pub soi_options: ::std::os::raw::c_short,
    pub soi_linger: ::std::os::raw::c_short,
    pub soi_state: ::std::os::raw::c_short,
    pub soi_qlen: ::std::os::raw::c_short,
    pub soi_incqlen: ::std::os::raw::c_short,
    pub soi_qlimit: ::std::os::raw::c_short,
    pub soi_timeo: ::std::os::raw::c_short,
    pub soi_error: u_short,
    pub soi_oobmark: u32,
    pub soi_rcv: sockbuf_info,
    pub soi_snd: sockbuf_info,
    pub soi_kind: ::std::os::raw::c_int,
    pub rfu_1: u32,
    pub soi_proto: socket_info__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union socket_info__bindgen_ty_1 {
    pub pri_in: in_sockinfo,
    pub pri_tcp: tcp_sockinfo,
    pub pri_un: un_sockinfo,
    pub pri_ndrv: ndrv_info,
    pub pri_kern_event: kern_event_info,
    pub pri_kern_ctl: kern_ctl_info,
    _bindgen_union_align: [u64; 66usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct socket_fdinfo {
    pub pfi: proc_fileinfo,
    pub psi: socket_info,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct psem_info {
    pub psem_stat: vinfo_stat,
    pub psem_name: [::std::os::raw::c_char; 1024usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct psem_fdinfo {
    pub pfi: proc_fileinfo,
    pub pseminfo: psem_info,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pshm_info {
    pub pshm_stat: vinfo_stat,
    pub pshm_mappaddr: u64,
    pub pshm_name: [::std::os::raw::c_char; 1024usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pshm_fdinfo {
    pub pfi: proc_fileinfo,
    pub pshminfo: pshm_info,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pipe_info {
    pub pipe_stat: vinfo_stat,
    pub pipe_handle: u64,
    pub pipe_peerhandle: u64,
    pub pipe_status: ::std::os::raw::c_int,
    pub rfu_1: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pipe_fdinfo {
    pub pfi: proc_fileinfo,
    pub pipeinfo: pipe_info,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kqueue_info {
    pub kq_stat: vinfo_stat,
    pub kq_state: u32,
    pub rfu_1: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kqueue_dyninfo {
    pub kqdi_info: kqueue_info,
    pub kqdi_servicer: u64,
    pub kqdi_owner: u64,
    pub kqdi_sync_waiters: u32,
    pub kqdi_sync_waiter_qos: u8,
    pub kqdi_async_qos: u8,
    pub kqdi_request_state: u16,
    pub kqdi_events_qos: u8,
    pub _kqdi_reserved0: [u8; 7usize],
    pub _kqdi_reserved1: [u64; 4usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kqueue_fdinfo {
    pub pfi: proc_fileinfo,
    pub kqueueinfo: kqueue_info,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct appletalk_info {
    pub atalk_stat: vinfo_stat,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct appletalk_fdinfo {
    pub pfi: proc_fileinfo,
    pub appletalkinfo: appletalk_info,
}
pub type proc_info_udata_t = u64;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_fdinfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct proc_fileportinfo {
    pub proc_fileport: u32,
    pub proc_fdtype: u32,
}
extern "C" {
    #[doc = "@function proc_listpidspath"]
    #[doc = "@discussion A function which will search through the current"]
    #[doc = "processes looking for open file references which match"]
    #[doc = "a specified path or volume."]
    #[doc = "@param type types of processes to be searched (see proc_listpids)"]
    #[doc = "@param typeinfo adjunct information for type"]
    #[doc = "@param path file or volume path"]
    #[doc = "@param pathflags flags to control which files should be considered"]
    #[doc = "during the process search."]
    #[doc = "@param buffer a C array of int-sized values to be filled with"]
    #[doc = "process identifiers that hold an open file reference"]
    #[doc = "matching the specified path or volume.  Pass NULL to"]
    #[doc = "obtain the minimum buffer size needed to hold the"]
    #[doc = "currently active processes."]
    #[doc = "@param buffersize the size (in bytes) of the provided buffer."]
    #[doc = "@result the number of bytes of data returned in the provided buffer;"]
    #[doc = "-1 if an error was encountered;"]
    pub fn proc_listpidspath(
        type_: u32,
        typeinfo: u32,
        path: *const ::std::os::raw::c_char,
        pathflags: u32,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_listpids(
        type_: u32,
        typeinfo: u32,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_listallpids(
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_listpgrppids(
        pgrpid: pid_t,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_listchildpids(
        ppid: pid_t,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_pidinfo(
        pid: ::std::os::raw::c_int,
        flavor: ::std::os::raw::c_int,
        arg: u64,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_pidfdinfo(
        pid: ::std::os::raw::c_int,
        fd: ::std::os::raw::c_int,
        flavor: ::std::os::raw::c_int,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_pidfileportinfo(
        pid: ::std::os::raw::c_int,
        fileport: u32,
        flavor: ::std::os::raw::c_int,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_name(
        pid: ::std::os::raw::c_int,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_regionfilename(
        pid: ::std::os::raw::c_int,
        address: u64,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_kmsgbuf(
        buffer: *mut ::std::os::raw::c_void,
        buffersize: u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_pidpath(
        pid: ::std::os::raw::c_int,
        buffer: *mut ::std::os::raw::c_void,
        buffersize: u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_libversion(
        major: *mut ::std::os::raw::c_int,
        minor: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_pid_rusage(
        pid: ::std::os::raw::c_int,
        flavor: ::std::os::raw::c_int,
        buffer: *mut rusage_info_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_setpcontrol(control: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_track_dirty(pid: pid_t, flags: u32) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_set_dirty(pid: pid_t, dirty: bool) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_get_dirty(pid: pid_t, flags: *mut u32) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn proc_terminate(pid: pid_t, sig: *mut ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
pub type __builtin_va_list = [__va_list_tag; 1usize];
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __va_list_tag {
    pub gp_offset: ::std::os::raw::c_uint,
    pub fp_offset: ::std::os::raw::c_uint,
    pub overflow_arg_area: *mut ::std::os::raw::c_void,
    pub reg_save_area: *mut ::std::os::raw::c_void,
}
