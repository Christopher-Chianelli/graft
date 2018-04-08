/*
 * intercept_syscall.c - intercept grafted processes syscalls
 * Copyright (C) 2017  Christopher Chianelli
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <intercepts/intercepts.h>

#include <stdarg.h>

struct user_regs_struct regs;
// Note: linux system calls are listed here:
// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

#define MAX_VALID_SYSCALL (328)
const char *SYSCALL_NAMES[] = {
  "sys_read",
  "sys_write",
  "sys_open",
  "sys_close",
  "sys_stat",
  "sys_fstat",
  "sys_lstat",
  "sys_poll",
  "sys_lseek",
  "sys_mmap",
  "sys_mprotect",
  "sys_munmap",
  "sys_brk",
  "sys_rt_sigaction",
  "sys_rt_sigprocmask",
  "sys_rt_sigreturn",
  "sys_ioctl",
  "sys_pread64",
  "sys_pwrite64",
  "sys_readv",
  "sys_writev",
  "sys_access",
  "sys_pipe",
  "sys_select",
  "sys_sched_yield",
  "sys_mremap",
  "sys_msync",
  "sys_mincore",
  "sys_madvise",
  "sys_shmget",
  "sys_shmat",
  "sys_shmctl",
  "sys_dup",
  "sys_dup2",
  "sys_pause",
  "sys_nanosleep",
  "sys_getitimer",
  "sys_alarm",
  "sys_setitimer",
  "sys_getpid",
  "sys_sendfile",
  "sys_socket",
  "sys_connect",
  "sys_accept",
  "sys_sendto",
  "sys_recvfrom",
  "sys_sendmsg",
  "sys_recvmsg",
  "sys_shutdown",
  "sys_bind",
  "sys_listen",
  "sys_getsockname",
  "sys_getpeername",
  "sys_socketpair",
  "sys_setsockopt",
  "sys_getsockopt",
  "sys_clone",
  "sys_fork",
  "sys_vfork",
  "sys_execve",
  "sys_exit",
  "sys_wait4",
  "sys_kill",
  "sys_uname",
  "sys_semget",
  "sys_semop",
  "sys_semctl",
  "sys_shmdt",
  "sys_msgget"
  "sys_msgsnd",
  "sys_msgrcv",
  "sys_msgctl",
  "sys_fcntl",
  "sys_flock",
  "sys_fsync",
  "sys_fdatasync",
  "sys_truncate",
  "sys_ftruncate",
  "sys_getdents",
  "sys_getcwd",
  "sys_chdir",
  "sys_fchdir",
  "sys_rename",
  "sys_mkdir",
  "sys_rmdir",
  "sys_creat",
  "sys_link",
  "sys_unlink",
  "sys_symlink",
  "sys_readlink",
  "sys_chmod",
  "sys_fchmod",
  "sys_chown",
  "sys_fchown",
  "sys_lchown",
  "sys_umask",
  "sys_gettimeofday",
  "sys_getrlimit",
  "sys_getrusage",
  "sys_sysinfo",
  "sys_times",
  "sys_ptrace",
  "sys_getuid",
  "sys_syslog",
  "sys_getgid",
  "sys_setuid",
  "sys_setgid",
  "sys_geteuid",
  "sys_getegid",
  "sys_setpgid",
  "sys_getppid",
  "sys_getpgrp",
  "sys_setsid",
  "sys_setreuid",
  "sys_setregid",
  "sys_getgroups",
  "sys_setgroups",
  "sys_setresuid",
  "sys_getresuid",
  "sys_setresgid",
  "sys_getresgid",
  "sys_getpgid",
  "sys_setfsuid",
  "sys_setfsgid",
  "sys_getsid",
  "sys_capget"
  "sys_capset",
  "sys_rt_sigpending",
  "sys_rt_sigtimedwait",
  "sys_rt_sigqueueinfo",
  "sys_rt_sigsuspend",
  "sys_sigaltstack",
  "sys_utime",
  "sys_mknod",
  "sys_uselib",
  "sys_personality",
  "sys_ustat",
  "sys_statfs",
  "sys_fstatfs",
  "sys_sysfs",
  "sys_getpriority",
  "sys_setpriority",
  "sys_sched_setparam",
  "sys_sched_getparam",
  "sys_sched_setscheduler",
  "sys_sched_getscheduler",
  "sys_sched_get_priority_max",
  "sys_sched_get_priority_min",
  "sys_sched_rr_get_interval",
  "sys_mlock",
  "sys_munlock",
  "sys_mlockall",
  "sys_munlockall",
  "sys_vhangup",
  "sys_modify_ldt",
  "sys_pivot_root",
  "sys__sysctl",
  "sys_prctl",
  "sys_arch_prctl",
  "sys_adjtimex",
  "sys_setrlimit",
  "sys_chroot",
  "sys_sync",
  "sys_acct",
  "sys_settimeofday",
  "sys_mount",
  "sys_umount2",
  "sys_swapon",
  "sys_swapoff",
  "sys_reboot",
  "sys_sethostname",
  "sys_setdomainname",
  "sys_iopl",
  "sys_ioperm",
  "sys_create_module",
  "sys_init_module",
  "sys_delete_module",
  "sys_get_kernel_syms",
  "sys_query_module",
  "sys_quotactl",
  "sys_nfsservctl",
  "sys_getpmsg",
  "sys_putpmsg",
  "sys_afs_syscall",
  "sys_tuxcall",
  "sys_security",
  "sys_gettid",
  "sys_readahead",
  "sys_setxattr",
  "sys_lsetxattr",
  "sys_fsetxattr",
  "sys_getxattr",
  "sys_lgetxattr",
  "sys_fgetxattr",
  "sys_listxattr",
  "sys_llistxattr",
  "sys_flistxattr",
  "sys_removexattr",
  "sys_lremovexattr",
  "sys_fremovexattr",
  "sys_tkill",
  "sys_time",
  "sys_futex",
  "sys_sched_setaffinity",
  "sys_sched_getaffinity",
  "sys_set_thread_area",
  "sys_io_setup",
  "sys_io_destroy",
  "sys_io_getevents",
  "sys_io_submit",
  "sys_io_cancel",
  "sys_get_thread_area",
  "sys_lookup_dcookie",
  "sys_epoll_create",
  "sys_epoll_ctl_old",
  "sys_epoll_wait_old",
  "sys_remap_file_pages",
  "sys_getdents64",
  "sys_set_tid_address",
  "sys_restart_syscall",
  "sys_semtimedop",
  "sys_fadvise64",
  "sys_timer_create",
  "sys_timer_settime",
  "sys_timer_gettime",
  "sys_timer_getoverrun",
  "sys_timer_delete",
  "sys_clock_settime",
  "sys_clock_gettime",
  "sys_clock_getres",
  "sys_clock_nanosleep",
  "sys_exit_group",
  "sys_epool_wait",
  "sys_epoll_ctl",
  "sys_tgkill",
  "sys_utimes",
  "sys_vserver",
  "sys_mbind",
  "sys_set_mempolicy",
  "sys_get_mempolicy",
  "sys_mq_open",
  "sys_mq_unlink",
  "sys_mq_timedsend",
  "sys_mq_timedreceive",
  "sys_mq_notify",
  "sys_mq_getsetattr",
  "sys_kexec_load",
  "sys_waitid",
  "sys_add_key",
  "sys_request_key",
  "sys_keyctl",
  "sys_ioprio_set",
  "sys_ioprio_get",
  "sys_inotify_init",
  "sys_inotify_add_watch",
  "sys_inotify_rm_watch",
  "sys_migrate_pages",
  "sys_openat",
  "sys_mkdirat",
  "sys_mknodat",
  "sys_fchownat",
  "sys_futimesat",
  "sys_newfstatat",
  "sys_unlinkat",
  "sys_renameat",
  "sys_linkat",
  "sys_symlinkat",
  "sys_readlinkat",
  "sys_fchmodat",
  "sys_faccessat",
  "sys_pselect6",
  "sys_ppoll",
  "sys_unshare",
  "sys_set_robust_list",
  "sys_get_robust_list",
  "sys_splice",
  "sys_tee",
  "sys_sync_file_range",
  "sys_vmsplice",
  "sys_move_pages",
  "sys_utimensat",
  "sys_epoll_pwait",
  "sys_signalfd",
  "sys_timerfd_create",
  "sys_eventfd",
  "sys_fallocate",
  "sys_timerfd_settime",
  "sys_timerfd_gettime",
  "sys_accept4",
  "sys_signalfd4",
  "sys_eventfd2",
  "sys_epoll_create1",
  "sys_dup3",
  "sys_pipe2",
  "sys_inotify_init1",
  "sys_preadv",
  "sys_pwritev",
  "sys_rt_tgsigqueueinfo",
  "sys_perf_event_open",
  "sys_recvmmsg",
  "sys_fanotify_init",
  "sys_fanotify_mark",
  "sys_prlimit64",
  "sys_name_to_handle_at",
  "sys_open_by_handle_at",
  "sys_clock_adjtime",
  "sys_syncfs",
  "sys_sendmmsg",
  "sys_setns",
  "sys_getcpu",
  "sys_process_vm_readv",
  "sys_process_vm_writev",
  "sys_kcmp",
  "sys_finit_modle",
  "sys_sched_setattr",
  "sys_sched_getattr",
  "sys_renameat2",
  "sys_seccomp",
  "sys_getrandom",
  "sys_memfd_create",
  "sys_kexec_file_load",
  "sys_bpf",
  "stub_execveat",
  "userfaultfd",
  "membarrier",
  "mlock2",
  "copy_file_range",
  "preadv2",
  "pwritev2"
};

void intercept_start(struct graft_process_data *child) {
  ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
  #ifdef __x86_64__
  child->params[0] = regs.orig_rax;
  child->params[1] = regs.rdi;
  child->params[2] = regs.rsi;
  child->params[3] = regs.rdx;
  child->params[4] = regs.r10;
  child->params[5] = regs.r8;
  child->params[6] = regs.r9;
  child->syscall_out = regs.rax;
  child->stack_p = regs.rsp;
  #elif defined __i386__
  child->params[0] = regs.orig_eax;
  child->params[1] = regs.ebx;
  child->params[2] = regs.ecx;
  child->params[3] = regs.edx;
  child->params[4] = regs.esi;
  child->params[5] = regs.edi;
  child->params[6] = regs.ebp;
  child->syscall_out = regs.eax;
  child->stack_p = regs.esp;
  #endif
}

void intercept_end(struct graft_process_data *child) {
  child->in_syscall = !child->in_syscall;
}

void set_syscall_params(struct graft_process_data *child) {
  #ifdef __x86_64__
  regs.orig_rax = child->params[0];
  regs.rdi = child->params[1];
  regs.rsi = child->params[2];
  regs.rdx = child->params[3];
  regs.r10 = child->params[4];
  regs.r8 = child->params[5];
  regs.r9 = child->params[6];
  #elif defined __i386__
  regs.orig_eax = child->params[0];
  regs.ebx = child->params[1];
  regs.ecx = child->params[2];
  regs.edx = child->params[3];
  regs.esi = child->params[4];
  regs.edi = child->params[5];
  regs.ebp = child->params[6];
  #endif
  ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
}

void set_syscall_out(struct graft_process_data *child) {
  #ifdef __x86_64__
  regs.rax = child->syscall_out;
  #elif defined __i386__
  regs.eax = child->syscall_out;
  #endif
  ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
}

static int is_data_binary(char *buf, int count) {
  if (buf[count] != '\0') {
    return 1;
  }
  else {
    for (int i = 0; i < count; i++) {
      if (buf[i] <= '\0') {
        return 1;
      }
    }
    return 0;
  }
}

void print_binary_data(void const * const ptr, size_t const size)
{
    unsigned char *b = (unsigned char*) ptr;

    printf("0x");
    for (int i=size-1;i>=0;i--) {
        printf("%02x", b[i]);
    }
}

static void graft_print_buffer(char *buf, int count) {
  if (NULL == buf) {
    printf("(NULL)");
    return;
  }
  int to_print = (count < 60) ? count : 60;
  if (is_data_binary(buf,to_print)) {
    print_binary_data(buf, to_print);
  }
  else {
    printf("%s", buf);
  }
}

const char *get_syscall_name(int syscall) {
  switch (syscall) {
    case SYS_write:
      return "sys_write";
    case SYS_read:
      return "sys_read";
    case SYS_open:
      return "sys_open";
    case SYS_openat:
      return "sys_openat";
    default:
      return SYSCALL_NAMES[syscall];
  }
}

void graft_log_intercept(int syscall, ...) {
  va_list ap;

  va_start (ap, syscall);

  int fd, count, flags, mode;
  char *buf, *filename;

  switch (syscall) {
    // fd buf count
    case SYS_read: case SYS_write:
      fd = va_arg(ap,int);
      buf = va_arg(ap,char *);
      count = va_arg(ap,int);
      printf("%s %d %d ", get_syscall_name(syscall), fd, count);
      graft_print_buffer(buf, count);
      printf("\n");
      break;

    // filename flags mode
    case SYS_open:
      filename = va_arg(ap, char *);
      flags = va_arg(ap, int);
      mode = va_arg(ap,int);
      printf("%s %s %d %d\n", get_syscall_name(syscall), filename, flags, mode);
      break;

    // dfd filename flags mode
    case SYS_openat:
      fd = va_arg(ap, int);
      filename = va_arg(ap, char *);
      flags = va_arg(ap, int);
      mode = va_arg(ap, int);
      printf("%s %d %s %d %d\n", get_syscall_name(syscall), fd, filename, flags, mode);
      break;

    default:
      if (syscall > MAX_VALID_SYSCALL) {
        printf("Invalid Syscall: %d\n", syscall);
      }
      else {
        printf("%s (Unimplemented)\n", get_syscall_name(syscall));
      }
      break;
  }
  va_end(ap);
}

void handle_syscall(struct graft_process_data *child) {
  intercept_start(child);
  switch (child->params[0]) {
  case SYS_read:
    graft_intercept_read(child);
    break;
  case SYS_write:
    graft_intercept_write(child);
    break;
  case SYS_open:
    graft_intercept_open(child);
    break;
  case SYS_openat:
    graft_intercept_open_at(child);
    break;
  default:
    graft_log_intercept((int) child->params[0]);
    break;
  }
  intercept_end(child);
}
