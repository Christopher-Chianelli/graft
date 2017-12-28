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

#include "graft.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>

struct user_regs_struct regs;

// Note: linux system calls are listed here:
// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

void intercept_start(struct graft_process_data *child) {
  ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
  #ifdef __x86_64__
  params[0] = regs.orig_rax;
  params[1] = regs.rdi;
  params[2] = regs.rsi;
  params[3] = regs.rdx;
  params[4] = regs.r10;
  params[5] = regs.r8;
  params[6] = regs.r9;
  syscall_out = regs.rax;
  #elif defined __i386__
  params[0] = regs.orig_eax;
  params[1] = regs.ebx;
  params[2] = regs.ecx;
  params[3] = regs.edx;
  params[4] = regs.esi;
  params[5] = regs.edi;
  params[6] = regs.ebp;
  syscall_out = regs.eax;
  #endif
}

void intercept_end(struct graft_process_data *child) {
  child->in_syscall = !child->in_syscall;
}

void intercept_read(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    unsigned int fd = (unsigned int) params[1];
    size_t count = (size_t) params[3];
    void *buf_loc = (void *) params[2];
    printf("Read called with "
        "%u\n%lu\n",
        fd,
        count);
  }
  else { /* Syscall exit */
    printf("Read returned "
      "with %llu\n", syscall_out);
  }
}

void intercept_write(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    unsigned int fd = (unsigned int) params[1];
    size_t count = (size_t) params[3];
    char *buf = (char *) read_from_process_memory(child->pid,
      (void *) params[2],
      count);

    printf("Write called with "
        "%u\n%s\n%lu\n",
        fd, buf,
        count);
    free(buf);
  }
  else { /* Syscall exit */
    printf("Write returned "
      "with %llu\n", syscall_out);
  }
}

void intercept_open(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    char *file_name = read_string_from_process_memory(child->pid, (void *) params[1]);
    int flags = (int) params[2];
    int mode = (int) params[3];
    char *abs_file_name = resolve_path_for_process(child, file_name);

    printf("Open called with "
        "%s\n%d\n%d\n",
        abs_file_name,
        flags,mode);

    free(file_name);
    free(abs_file_name);
  }
  else { /* Syscall exit */
    printf("Open returned "
      "with %llu\n", syscall_out);
  }
}

void handle_syscall(struct graft_process_data *child) {
  intercept_start(child);
  switch (params[0]) {
  case SYS_read:
    intercept_read(child);
    break;
  case SYS_write:
    intercept_write(child);
    break;
  case SYS_open:
    intercept_open(child);
    break;
  default:
    //printf("Syscall: %llu\n", params[0]);
    break;
  }
  intercept_end(child);
}
