#include <sys/syscall.h>

const char *SYSCALL_NAMES[] = {
#ifdef SYS_FAST_atomic_update
		[SYS_FAST_atomic_update] = "FAST_atomic_update",
#endif

#ifdef SYS_FAST_cmpxchg
	[SYS_FAST_cmpxchg] = "FAST_cmpxchg",
#endif

#ifdef SYS_FAST_cmpxchg64
	[SYS_FAST_cmpxchg64] = "FAST_cmpxchg64",
#endif

#ifdef SYS__llseek
	[SYS__llseek] = "_llseek",
#endif

#ifdef SYS__newselect
	[SYS__newselect] = "_newselect",
#endif

#ifdef SYS__sysctl
	[SYS__sysctl] = "_sysctl",
#endif

#ifdef SYS_accept
	[SYS_accept] = "accept",
#endif

#ifdef SYS_accept4
	[SYS_accept4] = "accept4",
#endif

#ifdef SYS_access
	[SYS_access] = "access",
#endif

#ifdef SYS_acct
	[SYS_acct] = "acct",
#endif

#ifdef SYS_acl_get
	[SYS_acl_get] = "acl_get",
#endif

#ifdef SYS_acl_set
	[SYS_acl_set] = "acl_set",
#endif

#ifdef SYS_add_key
	[SYS_add_key] = "add_key",
#endif

#ifdef SYS_adjtimex
	[SYS_adjtimex] = "adjtimex",
#endif

#ifdef SYS_afs_syscall
	[SYS_afs_syscall] = "afs_syscall",
#endif

#ifdef SYS_alarm
	[SYS_alarm] = "alarm",
#endif

#ifdef SYS_alloc_hugepages
	[SYS_alloc_hugepages] = "alloc_hugepages",
#endif

#ifdef SYS_arch_prctl
	[SYS_arch_prctl] = "arch_prctl",
#endif

#ifdef SYS_arm_fadvise64_64
	[SYS_arm_fadvise64_64] = "arm_fadvise64_64",
#endif

#ifdef SYS_arm_sync_file_range
	[SYS_arm_sync_file_range] = "arm_sync_file_range",
#endif

#ifdef SYS_atomic_barrier
	[SYS_atomic_barrier] = "atomic_barrier",
#endif

#ifdef SYS_atomic_cmpxchg_32
	[SYS_atomic_cmpxchg_32] = "atomic_cmpxchg_32",
#endif

#ifdef SYS_attrctl
	[SYS_attrctl] = "attrctl",
#endif

#ifdef SYS_bdflush
	[SYS_bdflush] = "bdflush",
#endif

#ifdef SYS_bind
	[SYS_bind] = "bind",
#endif

#ifdef SYS_bpf
	[SYS_bpf] = "bpf",
#endif

#ifdef SYS_break
	[SYS_break] = "break",
#endif

#ifdef SYS_brk
	[SYS_brk] = "brk",
#endif

#ifdef SYS_cachectl
	[SYS_cachectl] = "cachectl",
#endif

#ifdef SYS_cacheflush
	[SYS_cacheflush] = "cacheflush",
#endif

#ifdef SYS_capget
	[SYS_capget] = "capget",
#endif

#ifdef SYS_capset
	[SYS_capset] = "capset",
#endif

#ifdef SYS_chdir
	[SYS_chdir] = "chdir",
#endif

#ifdef SYS_chmod
	[SYS_chmod] = "chmod",
#endif

#ifdef SYS_chown
	[SYS_chown] = "chown",
#endif

#ifdef SYS_chown32
	[SYS_chown32] = "chown32",
#endif

#ifdef SYS_chroot
	[SYS_chroot] = "chroot",
#endif

#ifdef SYS_clock_adjtime
	[SYS_clock_adjtime] = "clock_adjtime",
#endif

#ifdef SYS_clock_getres
	[SYS_clock_getres] = "clock_getres",
#endif

#ifdef SYS_clock_gettime
	[SYS_clock_gettime] = "clock_gettime",
#endif

#ifdef SYS_clock_nanosleep
	[SYS_clock_nanosleep] = "clock_nanosleep",
#endif

#ifdef SYS_clock_settime
	[SYS_clock_settime] = "clock_settime",
#endif

#ifdef SYS_clone
	[SYS_clone] = "clone",
#endif

#ifdef SYS_clone2
	[SYS_clone2] = "clone2",
#endif

#ifdef SYS_close
	[SYS_close] = "close",
#endif

#ifdef SYS_cmpxchg_badaddr
	[SYS_cmpxchg_badaddr] = "cmpxchg_badaddr",
#endif

#ifdef SYS_connect
	[SYS_connect] = "connect",
#endif

#ifdef SYS_copy_file_range
	[SYS_copy_file_range] = "copy_file_range",
#endif

#ifdef SYS_creat
	[SYS_creat] = "creat",
#endif

#ifdef SYS_create_module
	[SYS_create_module] = "create_module",
#endif

#ifdef SYS_delete_module
	[SYS_delete_module] = "delete_module",
#endif

#ifdef SYS_dipc
	[SYS_dipc] = "dipc",
#endif

#ifdef SYS_dup
	[SYS_dup] = "dup",
#endif

#ifdef SYS_dup2
	[SYS_dup2] = "dup2",
#endif

#ifdef SYS_dup3
	[SYS_dup3] = "dup3",
#endif

#ifdef SYS_epoll_create
	[SYS_epoll_create] = "epoll_create",
#endif

#ifdef SYS_epoll_create1
	[SYS_epoll_create1] = "epoll_create1",
#endif

#ifdef SYS_epoll_ctl
	[SYS_epoll_ctl] = "epoll_ctl",
#endif

#ifdef SYS_epoll_ctl_old
	[SYS_epoll_ctl_old] = "epoll_ctl_old",
#endif

#ifdef SYS_epoll_pwait
	[SYS_epoll_pwait] = "epoll_pwait",
#endif

#ifdef SYS_epoll_wait
	[SYS_epoll_wait] = "epoll_wait",
#endif

#ifdef SYS_epoll_wait_old
	[SYS_epoll_wait_old] = "epoll_wait_old",
#endif

#ifdef SYS_eventfd
	[SYS_eventfd] = "eventfd",
#endif

#ifdef SYS_eventfd2
	[SYS_eventfd2] = "eventfd2",
#endif

#ifdef SYS_exec_with_loader
	[SYS_exec_with_loader] = "exec_with_loader",
#endif

#ifdef SYS_execv
	[SYS_execv] = "execv",
#endif

#ifdef SYS_execve
	[SYS_execve] = "execve",
#endif

#ifdef SYS_execveat
	[SYS_execveat] = "execveat",
#endif

#ifdef SYS_exit
	[SYS_exit] = "exit",
#endif

#ifdef SYS_exit_group
	[SYS_exit_group] = "exit_group",
#endif

#ifdef SYS_faccessat
	[SYS_faccessat] = "faccessat",
#endif

#ifdef SYS_fadvise64
	[SYS_fadvise64] = "fadvise64",
#endif

#ifdef SYS_fadvise64_64
	[SYS_fadvise64_64] = "fadvise64_64",
#endif

#ifdef SYS_fallocate
	[SYS_fallocate] = "fallocate",
#endif

#ifdef SYS_fanotify_init
	[SYS_fanotify_init] = "fanotify_init",
#endif

#ifdef SYS_fanotify_mark
	[SYS_fanotify_mark] = "fanotify_mark",
#endif

#ifdef SYS_fchdir
	[SYS_fchdir] = "fchdir",
#endif

#ifdef SYS_fchmod
	[SYS_fchmod] = "fchmod",
#endif

#ifdef SYS_fchmodat
	[SYS_fchmodat] = "fchmodat",
#endif

#ifdef SYS_fchown
	[SYS_fchown] = "fchown",
#endif

#ifdef SYS_fchown32
	[SYS_fchown32] = "fchown32",
#endif

#ifdef SYS_fchownat
	[SYS_fchownat] = "fchownat",
#endif

#ifdef SYS_fcntl
	[SYS_fcntl] = "fcntl",
#endif

#ifdef SYS_fcntl64
	[SYS_fcntl64] = "fcntl64",
#endif

#ifdef SYS_fdatasync
	[SYS_fdatasync] = "fdatasync",
#endif

#ifdef SYS_fgetxattr
	[SYS_fgetxattr] = "fgetxattr",
#endif

#ifdef SYS_finit_module
	[SYS_finit_module] = "finit_module",
#endif

#ifdef SYS_flistxattr
	[SYS_flistxattr] = "flistxattr",
#endif

#ifdef SYS_flock
	[SYS_flock] = "flock",
#endif

#ifdef SYS_fork
	[SYS_fork] = "fork",
#endif

#ifdef SYS_free_hugepages
	[SYS_free_hugepages] = "free_hugepages",
#endif

#ifdef SYS_fremovexattr
	[SYS_fremovexattr] = "fremovexattr",
#endif

#ifdef SYS_fsetxattr
	[SYS_fsetxattr] = "fsetxattr",
#endif

#ifdef SYS_fstat
	[SYS_fstat] = "fstat",
#endif

#ifdef SYS_fstat64
	[SYS_fstat64] = "fstat64",
#endif

#ifdef SYS_fstatat64
	[SYS_fstatat64] = "fstatat64",
#endif

#ifdef SYS_fstatfs
	[SYS_fstatfs] = "fstatfs",
#endif

#ifdef SYS_fstatfs64
	[SYS_fstatfs64] = "fstatfs64",
#endif

#ifdef SYS_fsync
	[SYS_fsync] = "fsync",
#endif

#ifdef SYS_ftime
	[SYS_ftime] = "ftime",
#endif

#ifdef SYS_ftruncate
	[SYS_ftruncate] = "ftruncate",
#endif

#ifdef SYS_ftruncate64
	[SYS_ftruncate64] = "ftruncate64",
#endif

#ifdef SYS_futex
	[SYS_futex] = "futex",
#endif

#ifdef SYS_futimesat
	[SYS_futimesat] = "futimesat",
#endif

#ifdef SYS_get_kernel_syms
	[SYS_get_kernel_syms] = "get_kernel_syms",
#endif

#ifdef SYS_get_mempolicy
	[SYS_get_mempolicy] = "get_mempolicy",
#endif

#ifdef SYS_get_robust_list
	[SYS_get_robust_list] = "get_robust_list",
#endif

#ifdef SYS_get_thread_area
	[SYS_get_thread_area] = "get_thread_area",
#endif

#ifdef SYS_getcpu
	[SYS_getcpu] = "getcpu",
#endif

#ifdef SYS_getcwd
	[SYS_getcwd] = "getcwd",
#endif

#ifdef SYS_getdents
	[SYS_getdents] = "getdents",
#endif

#ifdef SYS_getdents64
	[SYS_getdents64] = "getdents64",
#endif

#ifdef SYS_getdomainname
	[SYS_getdomainname] = "getdomainname",
#endif

#ifdef SYS_getdtablesize
	[SYS_getdtablesize] = "getdtablesize",
#endif

#ifdef SYS_getegid
	[SYS_getegid] = "getegid",
#endif

#ifdef SYS_getegid32
	[SYS_getegid32] = "getegid32",
#endif

#ifdef SYS_geteuid
	[SYS_geteuid] = "geteuid",
#endif

#ifdef SYS_geteuid32
	[SYS_geteuid32] = "geteuid32",
#endif

#ifdef SYS_getgid
	[SYS_getgid] = "getgid",
#endif

#ifdef SYS_getgid32
	[SYS_getgid32] = "getgid32",
#endif

#ifdef SYS_getgroups
	[SYS_getgroups] = "getgroups",
#endif

#ifdef SYS_getgroups32
	[SYS_getgroups32] = "getgroups32",
#endif

#ifdef SYS_gethostname
	[SYS_gethostname] = "gethostname",
#endif

#ifdef SYS_getitimer
	[SYS_getitimer] = "getitimer",
#endif

#ifdef SYS_getpagesize
	[SYS_getpagesize] = "getpagesize",
#endif

#ifdef SYS_getpeername
	[SYS_getpeername] = "getpeername",
#endif

#ifdef SYS_getpgid
	[SYS_getpgid] = "getpgid",
#endif

#ifdef SYS_getpgrp
	[SYS_getpgrp] = "getpgrp",
#endif

#ifdef SYS_getpid
	[SYS_getpid] = "getpid",
#endif

#ifdef SYS_getpmsg
	[SYS_getpmsg] = "getpmsg",
#endif

#ifdef SYS_getppid
	[SYS_getppid] = "getppid",
#endif

#ifdef SYS_getpriority
	[SYS_getpriority] = "getpriority",
#endif

#ifdef SYS_getrandom
	[SYS_getrandom] = "getrandom",
#endif

#ifdef SYS_getresgid
	[SYS_getresgid] = "getresgid",
#endif

#ifdef SYS_getresgid32
	[SYS_getresgid32] = "getresgid32",
#endif

#ifdef SYS_getresuid
	[SYS_getresuid] = "getresuid",
#endif

#ifdef SYS_getresuid32
	[SYS_getresuid32] = "getresuid32",
#endif

#ifdef SYS_getrlimit
	[SYS_getrlimit] = "getrlimit",
#endif

#ifdef SYS_getrusage
	[SYS_getrusage] = "getrusage",
#endif

#ifdef SYS_getsid
	[SYS_getsid] = "getsid",
#endif

#ifdef SYS_getsockname
	[SYS_getsockname] = "getsockname",
#endif

#ifdef SYS_getsockopt
	[SYS_getsockopt] = "getsockopt",
#endif

#ifdef SYS_gettid
	[SYS_gettid] = "gettid",
#endif

#ifdef SYS_gettimeofday
	[SYS_gettimeofday] = "gettimeofday",
#endif

#ifdef SYS_getuid
	[SYS_getuid] = "getuid",
#endif

#ifdef SYS_getuid32
	[SYS_getuid32] = "getuid32",
#endif

#ifdef SYS_getunwind
	[SYS_getunwind] = "getunwind",
#endif

#ifdef SYS_getxattr
	[SYS_getxattr] = "getxattr",
#endif

#ifdef SYS_getxgid
	[SYS_getxgid] = "getxgid",
#endif

#ifdef SYS_getxpid
	[SYS_getxpid] = "getxpid",
#endif

#ifdef SYS_getxuid
	[SYS_getxuid] = "getxuid",
#endif

#ifdef SYS_gtty
	[SYS_gtty] = "gtty",
#endif

#ifdef SYS_idle
	[SYS_idle] = "idle",
#endif

#ifdef SYS_init_module
	[SYS_init_module] = "init_module",
#endif

#ifdef SYS_inotify_add_watch
	[SYS_inotify_add_watch] = "inotify_add_watch",
#endif

#ifdef SYS_inotify_init
	[SYS_inotify_init] = "inotify_init",
#endif

#ifdef SYS_inotify_init1
	[SYS_inotify_init1] = "inotify_init1",
#endif

#ifdef SYS_inotify_rm_watch
	[SYS_inotify_rm_watch] = "inotify_rm_watch",
#endif

#ifdef SYS_io_cancel
	[SYS_io_cancel] = "io_cancel",
#endif

#ifdef SYS_io_destroy
	[SYS_io_destroy] = "io_destroy",
#endif

#ifdef SYS_io_getevents
	[SYS_io_getevents] = "io_getevents",
#endif

#ifdef SYS_io_setup
	[SYS_io_setup] = "io_setup",
#endif

#ifdef SYS_io_submit
	[SYS_io_submit] = "io_submit",
#endif

#ifdef SYS_ioctl
	[SYS_ioctl] = "ioctl",
#endif

#ifdef SYS_ioperm
	[SYS_ioperm] = "ioperm",
#endif

#ifdef SYS_iopl
	[SYS_iopl] = "iopl",
#endif

#ifdef SYS_ioprio_get
	[SYS_ioprio_get] = "ioprio_get",
#endif

#ifdef SYS_ioprio_set
	[SYS_ioprio_set] = "ioprio_set",
#endif

#ifdef SYS_ipc
	[SYS_ipc] = "ipc",
#endif

#ifdef SYS_kcmp
	[SYS_kcmp] = "kcmp",
#endif

#ifdef SYS_kern_features
	[SYS_kern_features] = "kern_features",
#endif

#ifdef SYS_kexec_file_load
	[SYS_kexec_file_load] = "kexec_file_load",
#endif

#ifdef SYS_kexec_load
	[SYS_kexec_load] = "kexec_load",
#endif

#ifdef SYS_keyctl
	[SYS_keyctl] = "keyctl",
#endif

#ifdef SYS_kill
	[SYS_kill] = "kill",
#endif

#ifdef SYS_lchown
	[SYS_lchown] = "lchown",
#endif

#ifdef SYS_lchown32
	[SYS_lchown32] = "lchown32",
#endif

#ifdef SYS_lgetxattr
	[SYS_lgetxattr] = "lgetxattr",
#endif

#ifdef SYS_link
	[SYS_link] = "link",
#endif

#ifdef SYS_linkat
	[SYS_linkat] = "linkat",
#endif

#ifdef SYS_listen
	[SYS_listen] = "listen",
#endif

#ifdef SYS_listxattr
	[SYS_listxattr] = "listxattr",
#endif

#ifdef SYS_llistxattr
	[SYS_llistxattr] = "llistxattr",
#endif

#ifdef SYS_llseek
	[SYS_llseek] = "llseek",
#endif

#ifdef SYS_lock
	[SYS_lock] = "lock",
#endif

#ifdef SYS_lookup_dcookie
	[SYS_lookup_dcookie] = "lookup_dcookie",
#endif

#ifdef SYS_lremovexattr
	[SYS_lremovexattr] = "lremovexattr",
#endif

#ifdef SYS_lseek
	[SYS_lseek] = "lseek",
#endif

#ifdef SYS_lsetxattr
	[SYS_lsetxattr] = "lsetxattr",
#endif

#ifdef SYS_lstat
	[SYS_lstat] = "lstat",
#endif

#ifdef SYS_lstat64
	[SYS_lstat64] = "lstat64",
#endif

#ifdef SYS_madvise
	[SYS_madvise] = "madvise",
#endif

#ifdef SYS_mbind
	[SYS_mbind] = "mbind",
#endif

#ifdef SYS_membarrier
	[SYS_membarrier] = "membarrier",
#endif

#ifdef SYS_memfd_create
	[SYS_memfd_create] = "memfd_create",
#endif

#ifdef SYS_memory_ordering
	[SYS_memory_ordering] = "memory_ordering",
#endif

#ifdef SYS_migrate_pages
	[SYS_migrate_pages] = "migrate_pages",
#endif

#ifdef SYS_mincore
	[SYS_mincore] = "mincore",
#endif

#ifdef SYS_mkdir
	[SYS_mkdir] = "mkdir",
#endif

#ifdef SYS_mkdirat
	[SYS_mkdirat] = "mkdirat",
#endif

#ifdef SYS_mknod
	[SYS_mknod] = "mknod",
#endif

#ifdef SYS_mknodat
	[SYS_mknodat] = "mknodat",
#endif

#ifdef SYS_mlock
	[SYS_mlock] = "mlock",
#endif

#ifdef SYS_mlock2
	[SYS_mlock2] = "mlock2",
#endif

#ifdef SYS_mlockall
	[SYS_mlockall] = "mlockall",
#endif

#ifdef SYS_mmap
	[SYS_mmap] = "mmap",
#endif

#ifdef SYS_mmap2
	[SYS_mmap2] = "mmap2",
#endif

#ifdef SYS_modify_ldt
	[SYS_modify_ldt] = "modify_ldt",
#endif

#ifdef SYS_mount
	[SYS_mount] = "mount",
#endif

#ifdef SYS_move_pages
	[SYS_move_pages] = "move_pages",
#endif

#ifdef SYS_mprotect
	[SYS_mprotect] = "mprotect",
#endif

#ifdef SYS_mpx
	[SYS_mpx] = "mpx",
#endif

#ifdef SYS_mq_getsetattr
	[SYS_mq_getsetattr] = "mq_getsetattr",
#endif

#ifdef SYS_mq_notify
	[SYS_mq_notify] = "mq_notify",
#endif

#ifdef SYS_mq_open
	[SYS_mq_open] = "mq_open",
#endif

#ifdef SYS_mq_timedreceive
	[SYS_mq_timedreceive] = "mq_timedreceive",
#endif

#ifdef SYS_mq_timedsend
	[SYS_mq_timedsend] = "mq_timedsend",
#endif

#ifdef SYS_mq_unlink
	[SYS_mq_unlink] = "mq_unlink",
#endif

#ifdef SYS_mremap
	[SYS_mremap] = "mremap",
#endif

#ifdef SYS_msgctl
	[SYS_msgctl] = "msgctl",
#endif

#ifdef SYS_msgget
	[SYS_msgget] = "msgget",
#endif

#ifdef SYS_msgrcv
	[SYS_msgrcv] = "msgrcv",
#endif

#ifdef SYS_msgsnd
	[SYS_msgsnd] = "msgsnd",
#endif

#ifdef SYS_msync
	[SYS_msync] = "msync",
#endif

#ifdef SYS_multiplexer
	[SYS_multiplexer] = "multiplexer",
#endif

#ifdef SYS_munlock
	[SYS_munlock] = "munlock",
#endif

#ifdef SYS_munlockall
	[SYS_munlockall] = "munlockall",
#endif

#ifdef SYS_munmap
	[SYS_munmap] = "munmap",
#endif

#ifdef SYS_name_to_handle_at
	[SYS_name_to_handle_at] = "name_to_handle_at",
#endif

#ifdef SYS_nanosleep
	[SYS_nanosleep] = "nanosleep",
#endif

#ifdef SYS_newfstatat
	[SYS_newfstatat] = "newfstatat",
#endif

#ifdef SYS_nfsservctl
	[SYS_nfsservctl] = "nfsservctl",
#endif

#ifdef SYS_ni_syscall
	[SYS_ni_syscall] = "ni_syscall",
#endif

#ifdef SYS_nice
	[SYS_nice] = "nice",
#endif

#ifdef SYS_old_adjtimex
	[SYS_old_adjtimex] = "old_adjtimex",
#endif

#ifdef SYS_oldfstat
	[SYS_oldfstat] = "oldfstat",
#endif

#ifdef SYS_oldlstat
	[SYS_oldlstat] = "oldlstat",
#endif

#ifdef SYS_oldolduname
	[SYS_oldolduname] = "oldolduname",
#endif

#ifdef SYS_oldstat
	[SYS_oldstat] = "oldstat",
#endif

#ifdef SYS_oldumount
	[SYS_oldumount] = "oldumount",
#endif

#ifdef SYS_olduname
	[SYS_olduname] = "olduname",
#endif

#ifdef SYS_open
	[SYS_open] = "open",
#endif

#ifdef SYS_open_by_handle_at
	[SYS_open_by_handle_at] = "open_by_handle_at",
#endif

#ifdef SYS_openat
	[SYS_openat] = "openat",
#endif

#ifdef SYS_osf_adjtime
	[SYS_osf_adjtime] = "osf_adjtime",
#endif

#ifdef SYS_osf_afs_syscall
	[SYS_osf_afs_syscall] = "osf_afs_syscall",
#endif

#ifdef SYS_osf_alt_plock
	[SYS_osf_alt_plock] = "osf_alt_plock",
#endif

#ifdef SYS_osf_alt_setsid
	[SYS_osf_alt_setsid] = "osf_alt_setsid",
#endif

#ifdef SYS_osf_alt_sigpending
	[SYS_osf_alt_sigpending] = "osf_alt_sigpending",
#endif

#ifdef SYS_osf_asynch_daemon
	[SYS_osf_asynch_daemon] = "osf_asynch_daemon",
#endif

#ifdef SYS_osf_audcntl
	[SYS_osf_audcntl] = "osf_audcntl",
#endif

#ifdef SYS_osf_audgen
	[SYS_osf_audgen] = "osf_audgen",
#endif

#ifdef SYS_osf_chflags
	[SYS_osf_chflags] = "osf_chflags",
#endif

#ifdef SYS_osf_execve
	[SYS_osf_execve] = "osf_execve",
#endif

#ifdef SYS_osf_exportfs
	[SYS_osf_exportfs] = "osf_exportfs",
#endif

#ifdef SYS_osf_fchflags
	[SYS_osf_fchflags] = "osf_fchflags",
#endif

#ifdef SYS_osf_fdatasync
	[SYS_osf_fdatasync] = "osf_fdatasync",
#endif

#ifdef SYS_osf_fpathconf
	[SYS_osf_fpathconf] = "osf_fpathconf",
#endif

#ifdef SYS_osf_fstat
	[SYS_osf_fstat] = "osf_fstat",
#endif

#ifdef SYS_osf_fstatfs
	[SYS_osf_fstatfs] = "osf_fstatfs",
#endif

#ifdef SYS_osf_fstatfs64
	[SYS_osf_fstatfs64] = "osf_fstatfs64",
#endif

#ifdef SYS_osf_fuser
	[SYS_osf_fuser] = "osf_fuser",
#endif

#ifdef SYS_osf_getaddressconf
	[SYS_osf_getaddressconf] = "osf_getaddressconf",
#endif

#ifdef SYS_osf_getdirentries
	[SYS_osf_getdirentries] = "osf_getdirentries",
#endif

#ifdef SYS_osf_getdomainname
	[SYS_osf_getdomainname] = "osf_getdomainname",
#endif

#ifdef SYS_osf_getfh
	[SYS_osf_getfh] = "osf_getfh",
#endif

#ifdef SYS_osf_getfsstat
	[SYS_osf_getfsstat] = "osf_getfsstat",
#endif

#ifdef SYS_osf_gethostid
	[SYS_osf_gethostid] = "osf_gethostid",
#endif

#ifdef SYS_osf_getitimer
	[SYS_osf_getitimer] = "osf_getitimer",
#endif

#ifdef SYS_osf_getlogin
	[SYS_osf_getlogin] = "osf_getlogin",
#endif

#ifdef SYS_osf_getmnt
	[SYS_osf_getmnt] = "osf_getmnt",
#endif

#ifdef SYS_osf_getrusage
	[SYS_osf_getrusage] = "osf_getrusage",
#endif

#ifdef SYS_osf_getsysinfo
	[SYS_osf_getsysinfo] = "osf_getsysinfo",
#endif

#ifdef SYS_osf_gettimeofday
	[SYS_osf_gettimeofday] = "osf_gettimeofday",
#endif

#ifdef SYS_osf_kloadcall
	[SYS_osf_kloadcall] = "osf_kloadcall",
#endif

#ifdef SYS_osf_kmodcall
	[SYS_osf_kmodcall] = "osf_kmodcall",
#endif

#ifdef SYS_osf_lstat
	[SYS_osf_lstat] = "osf_lstat",
#endif

#ifdef SYS_osf_memcntl
	[SYS_osf_memcntl] = "osf_memcntl",
#endif

#ifdef SYS_osf_mincore
	[SYS_osf_mincore] = "osf_mincore",
#endif

#ifdef SYS_osf_mount
	[SYS_osf_mount] = "osf_mount",
#endif

#ifdef SYS_osf_mremap
	[SYS_osf_mremap] = "osf_mremap",
#endif

#ifdef SYS_osf_msfs_syscall
	[SYS_osf_msfs_syscall] = "osf_msfs_syscall",
#endif

#ifdef SYS_osf_msleep
	[SYS_osf_msleep] = "osf_msleep",
#endif

#ifdef SYS_osf_mvalid
	[SYS_osf_mvalid] = "osf_mvalid",
#endif

#ifdef SYS_osf_mwakeup
	[SYS_osf_mwakeup] = "osf_mwakeup",
#endif

#ifdef SYS_osf_naccept
	[SYS_osf_naccept] = "osf_naccept",
#endif

#ifdef SYS_osf_nfssvc
	[SYS_osf_nfssvc] = "osf_nfssvc",
#endif

#ifdef SYS_osf_ngetpeername
	[SYS_osf_ngetpeername] = "osf_ngetpeername",
#endif

#ifdef SYS_osf_ngetsockname
	[SYS_osf_ngetsockname] = "osf_ngetsockname",
#endif

#ifdef SYS_osf_nrecvfrom
	[SYS_osf_nrecvfrom] = "osf_nrecvfrom",
#endif

#ifdef SYS_osf_nrecvmsg
	[SYS_osf_nrecvmsg] = "osf_nrecvmsg",
#endif

#ifdef SYS_osf_nsendmsg
	[SYS_osf_nsendmsg] = "osf_nsendmsg",
#endif

#ifdef SYS_osf_ntp_adjtime
	[SYS_osf_ntp_adjtime] = "osf_ntp_adjtime",
#endif

#ifdef SYS_osf_ntp_gettime
	[SYS_osf_ntp_gettime] = "osf_ntp_gettime",
#endif

#ifdef SYS_osf_old_creat
	[SYS_osf_old_creat] = "osf_old_creat",
#endif

#ifdef SYS_osf_old_fstat
	[SYS_osf_old_fstat] = "osf_old_fstat",
#endif

#ifdef SYS_osf_old_getpgrp
	[SYS_osf_old_getpgrp] = "osf_old_getpgrp",
#endif

#ifdef SYS_osf_old_killpg
	[SYS_osf_old_killpg] = "osf_old_killpg",
#endif

#ifdef SYS_osf_old_lstat
	[SYS_osf_old_lstat] = "osf_old_lstat",
#endif

#ifdef SYS_osf_old_open
	[SYS_osf_old_open] = "osf_old_open",
#endif

#ifdef SYS_osf_old_sigaction
	[SYS_osf_old_sigaction] = "osf_old_sigaction",
#endif

#ifdef SYS_osf_old_sigblock
	[SYS_osf_old_sigblock] = "osf_old_sigblock",
#endif

#ifdef SYS_osf_old_sigreturn
	[SYS_osf_old_sigreturn] = "osf_old_sigreturn",
#endif

#ifdef SYS_osf_old_sigsetmask
	[SYS_osf_old_sigsetmask] = "osf_old_sigsetmask",
#endif

#ifdef SYS_osf_old_sigvec
	[SYS_osf_old_sigvec] = "osf_old_sigvec",
#endif

#ifdef SYS_osf_old_stat
	[SYS_osf_old_stat] = "osf_old_stat",
#endif

#ifdef SYS_osf_old_vadvise
	[SYS_osf_old_vadvise] = "osf_old_vadvise",
#endif

#ifdef SYS_osf_old_vtrace
	[SYS_osf_old_vtrace] = "osf_old_vtrace",
#endif

#ifdef SYS_osf_old_wait
	[SYS_osf_old_wait] = "osf_old_wait",
#endif

#ifdef SYS_osf_oldquota
	[SYS_osf_oldquota] = "osf_oldquota",
#endif

#ifdef SYS_osf_pathconf
	[SYS_osf_pathconf] = "osf_pathconf",
#endif

#ifdef SYS_osf_pid_block
	[SYS_osf_pid_block] = "osf_pid_block",
#endif

#ifdef SYS_osf_pid_unblock
	[SYS_osf_pid_unblock] = "osf_pid_unblock",
#endif

#ifdef SYS_osf_plock
	[SYS_osf_plock] = "osf_plock",
#endif

#ifdef SYS_osf_priocntlset
	[SYS_osf_priocntlset] = "osf_priocntlset",
#endif

#ifdef SYS_osf_profil
	[SYS_osf_profil] = "osf_profil",
#endif

#ifdef SYS_osf_proplist_syscall
	[SYS_osf_proplist_syscall] = "osf_proplist_syscall",
#endif

#ifdef SYS_osf_reboot
	[SYS_osf_reboot] = "osf_reboot",
#endif

#ifdef SYS_osf_revoke
	[SYS_osf_revoke] = "osf_revoke",
#endif

#ifdef SYS_osf_sbrk
	[SYS_osf_sbrk] = "osf_sbrk",
#endif

#ifdef SYS_osf_security
	[SYS_osf_security] = "osf_security",
#endif

#ifdef SYS_osf_select
	[SYS_osf_select] = "osf_select",
#endif

#ifdef SYS_osf_set_program_attributes
	[SYS_osf_set_program_attributes] = "osf_set_program_attributes",
#endif

#ifdef SYS_osf_set_speculative
	[SYS_osf_set_speculative] = "osf_set_speculative",
#endif

#ifdef SYS_osf_sethostid
	[SYS_osf_sethostid] = "osf_sethostid",
#endif

#ifdef SYS_osf_setitimer
	[SYS_osf_setitimer] = "osf_setitimer",
#endif

#ifdef SYS_osf_setlogin
	[SYS_osf_setlogin] = "osf_setlogin",
#endif

#ifdef SYS_osf_setsysinfo
	[SYS_osf_setsysinfo] = "osf_setsysinfo",
#endif

#ifdef SYS_osf_settimeofday
	[SYS_osf_settimeofday] = "osf_settimeofday",
#endif

#ifdef SYS_osf_shmat
	[SYS_osf_shmat] = "osf_shmat",
#endif

#ifdef SYS_osf_signal
	[SYS_osf_signal] = "osf_signal",
#endif

#ifdef SYS_osf_sigprocmask
	[SYS_osf_sigprocmask] = "osf_sigprocmask",
#endif

#ifdef SYS_osf_sigsendset
	[SYS_osf_sigsendset] = "osf_sigsendset",
#endif

#ifdef SYS_osf_sigstack
	[SYS_osf_sigstack] = "osf_sigstack",
#endif

#ifdef SYS_osf_sigwaitprim
	[SYS_osf_sigwaitprim] = "osf_sigwaitprim",
#endif

#ifdef SYS_osf_sstk
	[SYS_osf_sstk] = "osf_sstk",
#endif

#ifdef SYS_osf_stat
	[SYS_osf_stat] = "osf_stat",
#endif

#ifdef SYS_osf_statfs
	[SYS_osf_statfs] = "osf_statfs",
#endif

#ifdef SYS_osf_statfs64
	[SYS_osf_statfs64] = "osf_statfs64",
#endif

#ifdef SYS_osf_subsys_info
	[SYS_osf_subsys_info] = "osf_subsys_info",
#endif

#ifdef SYS_osf_swapctl
	[SYS_osf_swapctl] = "osf_swapctl",
#endif

#ifdef SYS_osf_swapon
	[SYS_osf_swapon] = "osf_swapon",
#endif

#ifdef SYS_osf_syscall
	[SYS_osf_syscall] = "osf_syscall",
#endif

#ifdef SYS_osf_sysinfo
	[SYS_osf_sysinfo] = "osf_sysinfo",
#endif

#ifdef SYS_osf_table
	[SYS_osf_table] = "osf_table",
#endif

#ifdef SYS_osf_uadmin
	[SYS_osf_uadmin] = "osf_uadmin",
#endif

#ifdef SYS_osf_usleep_thread
	[SYS_osf_usleep_thread] = "osf_usleep_thread",
#endif

#ifdef SYS_osf_uswitch
	[SYS_osf_uswitch] = "osf_uswitch",
#endif

#ifdef SYS_osf_utc_adjtime
	[SYS_osf_utc_adjtime] = "osf_utc_adjtime",
#endif

#ifdef SYS_osf_utc_gettime
	[SYS_osf_utc_gettime] = "osf_utc_gettime",
#endif

#ifdef SYS_osf_utimes
	[SYS_osf_utimes] = "osf_utimes",
#endif

#ifdef SYS_osf_utsname
	[SYS_osf_utsname] = "osf_utsname",
#endif

#ifdef SYS_osf_wait4
	[SYS_osf_wait4] = "osf_wait4",
#endif

#ifdef SYS_osf_waitid
	[SYS_osf_waitid] = "osf_waitid",
#endif

#ifdef SYS_pause
	[SYS_pause] = "pause",
#endif

#ifdef SYS_pciconfig_iobase
	[SYS_pciconfig_iobase] = "pciconfig_iobase",
#endif

#ifdef SYS_pciconfig_read
	[SYS_pciconfig_read] = "pciconfig_read",
#endif

#ifdef SYS_pciconfig_write
	[SYS_pciconfig_write] = "pciconfig_write",
#endif

#ifdef SYS_perf_event_open
	[SYS_perf_event_open] = "perf_event_open",
#endif

#ifdef SYS_perfctr
	[SYS_perfctr] = "perfctr",
#endif

#ifdef SYS_perfmonctl
	[SYS_perfmonctl] = "perfmonctl",
#endif

#ifdef SYS_personality
	[SYS_personality] = "personality",
#endif

#ifdef SYS_pipe
	[SYS_pipe] = "pipe",
#endif

#ifdef SYS_pipe2
	[SYS_pipe2] = "pipe2",
#endif

#ifdef SYS_pivot_root
	[SYS_pivot_root] = "pivot_root",
#endif

#ifdef SYS_pkey_alloc
	[SYS_pkey_alloc] = "pkey_alloc",
#endif

#ifdef SYS_pkey_free
	[SYS_pkey_free] = "pkey_free",
#endif

#ifdef SYS_pkey_mprotect
	[SYS_pkey_mprotect] = "pkey_mprotect",
#endif

#ifdef SYS_poll
	[SYS_poll] = "poll",
#endif

#ifdef SYS_ppoll
	[SYS_ppoll] = "ppoll",
#endif

#ifdef SYS_prctl
	[SYS_prctl] = "prctl",
#endif

#ifdef SYS_pread64
	[SYS_pread64] = "pread64",
#endif

#ifdef SYS_preadv
	[SYS_preadv] = "preadv",
#endif

#ifdef SYS_preadv2
	[SYS_preadv2] = "preadv2",
#endif

#ifdef SYS_prlimit64
	[SYS_prlimit64] = "prlimit64",
#endif

#ifdef SYS_process_vm_readv
	[SYS_process_vm_readv] = "process_vm_readv",
#endif

#ifdef SYS_process_vm_writev
	[SYS_process_vm_writev] = "process_vm_writev",
#endif

#ifdef SYS_prof
	[SYS_prof] = "prof",
#endif

#ifdef SYS_profil
	[SYS_profil] = "profil",
#endif

#ifdef SYS_pselect6
	[SYS_pselect6] = "pselect6",
#endif

#ifdef SYS_ptrace
	[SYS_ptrace] = "ptrace",
#endif

#ifdef SYS_putpmsg
	[SYS_putpmsg] = "putpmsg",
#endif

#ifdef SYS_pwrite64
	[SYS_pwrite64] = "pwrite64",
#endif

#ifdef SYS_pwritev
	[SYS_pwritev] = "pwritev",
#endif

#ifdef SYS_pwritev2
	[SYS_pwritev2] = "pwritev2",
#endif

#ifdef SYS_query_module
	[SYS_query_module] = "query_module",
#endif

#ifdef SYS_quotactl
	[SYS_quotactl] = "quotactl",
#endif

#ifdef SYS_read
	[SYS_read] = "read",
#endif

#ifdef SYS_readahead
	[SYS_readahead] = "readahead",
#endif

#ifdef SYS_readdir
	[SYS_readdir] = "readdir",
#endif

#ifdef SYS_readlink
	[SYS_readlink] = "readlink",
#endif

#ifdef SYS_readlinkat
	[SYS_readlinkat] = "readlinkat",
#endif

#ifdef SYS_readv
	[SYS_readv] = "readv",
#endif

#ifdef SYS_reboot
	[SYS_reboot] = "reboot",
#endif

#ifdef SYS_recv
	[SYS_recv] = "recv",
#endif

#ifdef SYS_recvfrom
	[SYS_recvfrom] = "recvfrom",
#endif

#ifdef SYS_recvmmsg
	[SYS_recvmmsg] = "recvmmsg",
#endif

#ifdef SYS_recvmsg
	[SYS_recvmsg] = "recvmsg",
#endif

#ifdef SYS_remap_file_pages
	[SYS_remap_file_pages] = "remap_file_pages",
#endif

#ifdef SYS_removexattr
	[SYS_removexattr] = "removexattr",
#endif

#ifdef SYS_rename
	[SYS_rename] = "rename",
#endif

#ifdef SYS_renameat
	[SYS_renameat] = "renameat",
#endif

#ifdef SYS_renameat2
	[SYS_renameat2] = "renameat2",
#endif

#ifdef SYS_request_key
	[SYS_request_key] = "request_key",
#endif

#ifdef SYS_restart_syscall
	[SYS_restart_syscall] = "restart_syscall",
#endif

#ifdef SYS_rmdir
	[SYS_rmdir] = "rmdir",
#endif

#ifdef SYS_rt_sigaction
	[SYS_rt_sigaction] = "rt_sigaction",
#endif

#ifdef SYS_rt_sigpending
	[SYS_rt_sigpending] = "rt_sigpending",
#endif

#ifdef SYS_rt_sigprocmask
	[SYS_rt_sigprocmask] = "rt_sigprocmask",
#endif

#ifdef SYS_rt_sigqueueinfo
	[SYS_rt_sigqueueinfo] = "rt_sigqueueinfo",
#endif

#ifdef SYS_rt_sigreturn
	[SYS_rt_sigreturn] = "rt_sigreturn",
#endif

#ifdef SYS_rt_sigsuspend
	[SYS_rt_sigsuspend] = "rt_sigsuspend",
#endif

#ifdef SYS_rt_sigtimedwait
	[SYS_rt_sigtimedwait] = "rt_sigtimedwait",
#endif

#ifdef SYS_rt_tgsigqueueinfo
	[SYS_rt_tgsigqueueinfo] = "rt_tgsigqueueinfo",
#endif

#ifdef SYS_rtas
	[SYS_rtas] = "rtas",
#endif

#ifdef SYS_s390_guarded_storage
	[SYS_s390_guarded_storage] = "s390_guarded_storage",
#endif

#ifdef SYS_s390_pci_mmio_read
	[SYS_s390_pci_mmio_read] = "s390_pci_mmio_read",
#endif

#ifdef SYS_s390_pci_mmio_write
	[SYS_s390_pci_mmio_write] = "s390_pci_mmio_write",
#endif

#ifdef SYS_s390_runtime_instr
	[SYS_s390_runtime_instr] = "s390_runtime_instr",
#endif

#ifdef SYS_sched_get_affinity
	[SYS_sched_get_affinity] = "sched_get_affinity",
#endif

#ifdef SYS_sched_get_priority_max
	[SYS_sched_get_priority_max] = "sched_get_priority_max",
#endif

#ifdef SYS_sched_get_priority_min
	[SYS_sched_get_priority_min] = "sched_get_priority_min",
#endif

#ifdef SYS_sched_getaffinity
	[SYS_sched_getaffinity] = "sched_getaffinity",
#endif

#ifdef SYS_sched_getattr
	[SYS_sched_getattr] = "sched_getattr",
#endif

#ifdef SYS_sched_getparam
	[SYS_sched_getparam] = "sched_getparam",
#endif

#ifdef SYS_sched_getscheduler
	[SYS_sched_getscheduler] = "sched_getscheduler",
#endif

#ifdef SYS_sched_rr_get_interval
	[SYS_sched_rr_get_interval] = "sched_rr_get_interval",
#endif

#ifdef SYS_sched_set_affinity
	[SYS_sched_set_affinity] = "sched_set_affinity",
#endif

#ifdef SYS_sched_setaffinity
	[SYS_sched_setaffinity] = "sched_setaffinity",
#endif

#ifdef SYS_sched_setattr
	[SYS_sched_setattr] = "sched_setattr",
#endif

#ifdef SYS_sched_setparam
	[SYS_sched_setparam] = "sched_setparam",
#endif

#ifdef SYS_sched_setscheduler
	[SYS_sched_setscheduler] = "sched_setscheduler",
#endif

#ifdef SYS_sched_yield
	[SYS_sched_yield] = "sched_yield",
#endif

#ifdef SYS_seccomp
	[SYS_seccomp] = "seccomp",
#endif

#ifdef SYS_security
	[SYS_security] = "security",
#endif

#ifdef SYS_select
	[SYS_select] = "select",
#endif

#ifdef SYS_semctl
	[SYS_semctl] = "semctl",
#endif

#ifdef SYS_semget
	[SYS_semget] = "semget",
#endif

#ifdef SYS_semop
	[SYS_semop] = "semop",
#endif

#ifdef SYS_semtimedop
	[SYS_semtimedop] = "semtimedop",
#endif

#ifdef SYS_send
	[SYS_send] = "send",
#endif

#ifdef SYS_sendfile
	[SYS_sendfile] = "sendfile",
#endif

#ifdef SYS_sendfile64
	[SYS_sendfile64] = "sendfile64",
#endif

#ifdef SYS_sendmmsg
	[SYS_sendmmsg] = "sendmmsg",
#endif

#ifdef SYS_sendmsg
	[SYS_sendmsg] = "sendmsg",
#endif

#ifdef SYS_sendto
	[SYS_sendto] = "sendto",
#endif

#ifdef SYS_set_mempolicy
	[SYS_set_mempolicy] = "set_mempolicy",
#endif

#ifdef SYS_set_robust_list
	[SYS_set_robust_list] = "set_robust_list",
#endif

#ifdef SYS_set_thread_area
	[SYS_set_thread_area] = "set_thread_area",
#endif

#ifdef SYS_set_tid_address
	[SYS_set_tid_address] = "set_tid_address",
#endif

#ifdef SYS_setdomainname
	[SYS_setdomainname] = "setdomainname",
#endif

#ifdef SYS_setfsgid
	[SYS_setfsgid] = "setfsgid",
#endif

#ifdef SYS_setfsgid32
	[SYS_setfsgid32] = "setfsgid32",
#endif

#ifdef SYS_setfsuid
	[SYS_setfsuid] = "setfsuid",
#endif

#ifdef SYS_setfsuid32
	[SYS_setfsuid32] = "setfsuid32",
#endif

#ifdef SYS_setgid
	[SYS_setgid] = "setgid",
#endif

#ifdef SYS_setgid32
	[SYS_setgid32] = "setgid32",
#endif

#ifdef SYS_setgroups
	[SYS_setgroups] = "setgroups",
#endif

#ifdef SYS_setgroups32
	[SYS_setgroups32] = "setgroups32",
#endif

#ifdef SYS_sethae
	[SYS_sethae] = "sethae",
#endif

#ifdef SYS_sethostname
	[SYS_sethostname] = "sethostname",
#endif

#ifdef SYS_setitimer
	[SYS_setitimer] = "setitimer",
#endif

#ifdef SYS_setns
	[SYS_setns] = "setns",
#endif

#ifdef SYS_setpgid
	[SYS_setpgid] = "setpgid",
#endif

#ifdef SYS_setpgrp
	[SYS_setpgrp] = "setpgrp",
#endif

#ifdef SYS_setpriority
	[SYS_setpriority] = "setpriority",
#endif

#ifdef SYS_setregid
	[SYS_setregid] = "setregid",
#endif

#ifdef SYS_setregid32
	[SYS_setregid32] = "setregid32",
#endif

#ifdef SYS_setresgid
	[SYS_setresgid] = "setresgid",
#endif

#ifdef SYS_setresgid32
	[SYS_setresgid32] = "setresgid32",
#endif

#ifdef SYS_setresuid
	[SYS_setresuid] = "setresuid",
#endif

#ifdef SYS_setresuid32
	[SYS_setresuid32] = "setresuid32",
#endif

#ifdef SYS_setreuid
	[SYS_setreuid] = "setreuid",
#endif

#ifdef SYS_setreuid32
	[SYS_setreuid32] = "setreuid32",
#endif

#ifdef SYS_setrlimit
	[SYS_setrlimit] = "setrlimit",
#endif

#ifdef SYS_setsid
	[SYS_setsid] = "setsid",
#endif

#ifdef SYS_setsockopt
	[SYS_setsockopt] = "setsockopt",
#endif

#ifdef SYS_settimeofday
	[SYS_settimeofday] = "settimeofday",
#endif

#ifdef SYS_setuid
	[SYS_setuid] = "setuid",
#endif

#ifdef SYS_setuid32
	[SYS_setuid32] = "setuid32",
#endif

#ifdef SYS_setxattr
	[SYS_setxattr] = "setxattr",
#endif

#ifdef SYS_sgetmask
	[SYS_sgetmask] = "sgetmask",
#endif

#ifdef SYS_shmat
	[SYS_shmat] = "shmat",
#endif

#ifdef SYS_shmctl
	[SYS_shmctl] = "shmctl",
#endif

#ifdef SYS_shmdt
	[SYS_shmdt] = "shmdt",
#endif

#ifdef SYS_shmget
	[SYS_shmget] = "shmget",
#endif

#ifdef SYS_shutdown
	[SYS_shutdown] = "shutdown",
#endif

#ifdef SYS_sigaction
	[SYS_sigaction] = "sigaction",
#endif

#ifdef SYS_sigaltstack
	[SYS_sigaltstack] = "sigaltstack",
#endif

#ifdef SYS_signal
	[SYS_signal] = "signal",
#endif

#ifdef SYS_signalfd
	[SYS_signalfd] = "signalfd",
#endif

#ifdef SYS_signalfd4
	[SYS_signalfd4] = "signalfd4",
#endif

#ifdef SYS_sigpending
	[SYS_sigpending] = "sigpending",
#endif

#ifdef SYS_sigprocmask
	[SYS_sigprocmask] = "sigprocmask",
#endif

#ifdef SYS_sigreturn
	[SYS_sigreturn] = "sigreturn",
#endif

#ifdef SYS_sigsuspend
	[SYS_sigsuspend] = "sigsuspend",
#endif

#ifdef SYS_socket
	[SYS_socket] = "socket",
#endif

#ifdef SYS_socketcall
	[SYS_socketcall] = "socketcall",
#endif

#ifdef SYS_socketpair
	[SYS_socketpair] = "socketpair",
#endif

#ifdef SYS_splice
	[SYS_splice] = "splice",
#endif

#ifdef SYS_spu_create
	[SYS_spu_create] = "spu_create",
#endif

#ifdef SYS_spu_run
	[SYS_spu_run] = "spu_run",
#endif

#ifdef SYS_ssetmask
	[SYS_ssetmask] = "ssetmask",
#endif

#ifdef SYS_stat
	[SYS_stat] = "stat",
#endif

#ifdef SYS_stat64
	[SYS_stat64] = "stat64",
#endif

#ifdef SYS_statfs
	[SYS_statfs] = "statfs",
#endif

#ifdef SYS_statfs64
	[SYS_statfs64] = "statfs64",
#endif

#ifdef SYS_statx
	[SYS_statx] = "statx",
#endif

#ifdef SYS_stime
	[SYS_stime] = "stime",
#endif

#ifdef SYS_stty
	[SYS_stty] = "stty",
#endif

#ifdef SYS_subpage_prot
	[SYS_subpage_prot] = "subpage_prot",
#endif

#ifdef SYS_swapcontext
	[SYS_swapcontext] = "swapcontext",
#endif

#ifdef SYS_swapoff
	[SYS_swapoff] = "swapoff",
#endif

#ifdef SYS_swapon
	[SYS_swapon] = "swapon",
#endif

#ifdef SYS_switch_endian
	[SYS_switch_endian] = "switch_endian",
#endif

#ifdef SYS_symlink
	[SYS_symlink] = "symlink",
#endif

#ifdef SYS_symlinkat
	[SYS_symlinkat] = "symlinkat",
#endif

#ifdef SYS_sync
	[SYS_sync] = "sync",
#endif

#ifdef SYS_sync_file_range
	[SYS_sync_file_range] = "sync_file_range",
#endif

#ifdef SYS_sync_file_range2
	[SYS_sync_file_range2] = "sync_file_range2",
#endif

#ifdef SYS_syncfs
	[SYS_syncfs] = "syncfs",
#endif

#ifdef SYS_sys_debug_setcontext
	[SYS_sys_debug_setcontext] = "sys_debug_setcontext",
#endif

#ifdef SYS_sys_epoll_create
	[SYS_sys_epoll_create] = "sys_epoll_create",
#endif

#ifdef SYS_sys_epoll_ctl
	[SYS_sys_epoll_ctl] = "sys_epoll_ctl",
#endif

#ifdef SYS_sys_epoll_wait
	[SYS_sys_epoll_wait] = "sys_epoll_wait",
#endif

#ifdef SYS_syscall
	[SYS_syscall] = "syscall",
#endif

#ifdef SYS_sysfs
	[SYS_sysfs] = "sysfs",
#endif

#ifdef SYS_sysinfo
	[SYS_sysinfo] = "sysinfo",
#endif

#ifdef SYS_syslog
	[SYS_syslog] = "syslog",
#endif

#ifdef SYS_sysmips
	[SYS_sysmips] = "sysmips",
#endif

#ifdef SYS_tee
	[SYS_tee] = "tee",
#endif

#ifdef SYS_tgkill
	[SYS_tgkill] = "tgkill",
#endif

#ifdef SYS_time
	[SYS_time] = "time",
#endif

#ifdef SYS_timer_create
	[SYS_timer_create] = "timer_create",
#endif

#ifdef SYS_timer_delete
	[SYS_timer_delete] = "timer_delete",
#endif

#ifdef SYS_timer_getoverrun
	[SYS_timer_getoverrun] = "timer_getoverrun",
#endif

#ifdef SYS_timer_gettime
	[SYS_timer_gettime] = "timer_gettime",
#endif

#ifdef SYS_timer_settime
	[SYS_timer_settime] = "timer_settime",
#endif

#ifdef SYS_timerfd
	[SYS_timerfd] = "timerfd",
#endif

#ifdef SYS_timerfd_create
	[SYS_timerfd_create] = "timerfd_create",
#endif

#ifdef SYS_timerfd_gettime
	[SYS_timerfd_gettime] = "timerfd_gettime",
#endif

#ifdef SYS_timerfd_settime
	[SYS_timerfd_settime] = "timerfd_settime",
#endif

#ifdef SYS_times
	[SYS_times] = "times",
#endif

#ifdef SYS_tkill
	[SYS_tkill] = "tkill",
#endif

#ifdef SYS_truncate
	[SYS_truncate] = "truncate",
#endif

#ifdef SYS_truncate64
	[SYS_truncate64] = "truncate64",
#endif

#ifdef SYS_tuxcall
	[SYS_tuxcall] = "tuxcall",
#endif

#ifdef SYS_ugetrlimit
	[SYS_ugetrlimit] = "ugetrlimit",
#endif

#ifdef SYS_ulimit
	[SYS_ulimit] = "ulimit",
#endif

#ifdef SYS_umask
	[SYS_umask] = "umask",
#endif

#ifdef SYS_umount
	[SYS_umount] = "umount",
#endif

#ifdef SYS_umount2
	[SYS_umount2] = "umount2",
#endif

#ifdef SYS_uname
	[SYS_uname] = "uname",
#endif

#ifdef SYS_unlink
	[SYS_unlink] = "unlink",
#endif

#ifdef SYS_unlinkat
	[SYS_unlinkat] = "unlinkat",
#endif

#ifdef SYS_unshare
	[SYS_unshare] = "unshare",
#endif

#ifdef SYS_uselib
	[SYS_uselib] = "uselib",
#endif

#ifdef SYS_userfaultfd
	[SYS_userfaultfd] = "userfaultfd",
#endif

#ifdef SYS_ustat
	[SYS_ustat] = "ustat",
#endif

#ifdef SYS_utime
	[SYS_utime] = "utime",
#endif

#ifdef SYS_utimensat
	[SYS_utimensat] = "utimensat",
#endif

#ifdef SYS_utimes
	[SYS_utimes] = "utimes",
#endif

#ifdef SYS_utrap_install
	[SYS_utrap_install] = "utrap_install",
#endif

#ifdef SYS_vfork
	[SYS_vfork] = "vfork",
#endif

#ifdef SYS_vhangup
	[SYS_vhangup] = "vhangup",
#endif

#ifdef SYS_vm86
	[SYS_vm86] = "vm86",
#endif

#ifdef SYS_vm86old
	[SYS_vm86old] = "vm86old",
#endif

#ifdef SYS_vmsplice
	[SYS_vmsplice] = "vmsplice",
#endif

#ifdef SYS_vserver
	[SYS_vserver] = "vserver",
#endif

#ifdef SYS_wait4
	[SYS_wait4] = "wait4",
#endif

#ifdef SYS_waitid
	[SYS_waitid] = "waitid",
#endif

#ifdef SYS_waitpid
	[SYS_waitpid] = "waitpid",
#endif

#ifdef SYS_write
	[SYS_write] = "write",
#endif

#ifdef SYS_writev
	[SYS_writev] = "writev",
#endif
};
