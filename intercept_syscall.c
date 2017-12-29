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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>

struct user_regs_struct regs;
reg_v params[8];
reg_v syscall_out;
reg_v stack_p;

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
  stack_p = regs.rsp;
  #elif defined __i386__
  params[0] = regs.orig_eax;
  params[1] = regs.ebx;
  params[2] = regs.ecx;
  params[3] = regs.edx;
  params[4] = regs.esi;
  params[5] = regs.edi;
  params[6] = regs.ebp;
  syscall_out = regs.eax;
  stack_p = regs.esp;
  #endif
}

void intercept_end(struct graft_process_data *child) {
  child->in_syscall = !child->in_syscall;
}

static void set_syscall_params(struct graft_process_data *child) {
  #ifdef __x86_64__
  regs.orig_rax = params[0];
  regs.rdi = params[1];
  regs.rsi = params[2];
  regs.rdx = params[3];
  regs.r10 = params[4];
  regs.r8 = params[5];
  regs.r9 = params[6];
  #elif defined __i386__
  regs.orig_eax = params[0];
  regs.ebx = params[1];
  regs.ecx = params[2];
  regs.edx = params[3];
  regs.esi = params[4];
  regs.edi = params[5];
  regs.ebp = params[6];
  #endif
  ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
}

static void set_syscall_out(struct graft_process_data *child) {
  #ifdef __x86_64__
  regs.rax = syscall_out;
  #elif defined __i386__
  regs.eax = syscall_out;
  #endif
  ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
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
    char *file_name;
    if (((char *)params[1]) != NULL) {
      file_name = read_string_from_process_memory(child->pid, (void *) params[1]);
    }
    else {
      file_name = NULL;
    }
    int flags = (int) params[2];
    int mode = (int) params[3];
    char *abs_file_name;
    if (file_name != NULL) {
      abs_file_name = resolve_path_for_process(child, file_name);
    }
    else {
      abs_file_name = NULL;
    }

    if (abs_file_name == NULL) {
      printf("Open called with "
          "%s\n%d\n%d\n",
          "NULL",
          flags,mode);
    }
    else {
      printf("Open called with "
          "%s\n%d\n%d\n",
          abs_file_name,
          flags,mode);
    }

    struct graft_open_file_request request;
    request.file_path = abs_file_name;
    request.flags = flags;
    request.mode = mode;

    struct graft_open_file_response response = handle_open_file_request(request);
    if (!response.is_allowed) {
      params[2] = (reg_v) (O_RDONLY | O_WRONLY);
    }
    else {
      if (response.is_redirected) {
        printf("Redirecting to %s\n", response.new_file_path);
        void *new_file_path = write_temp_to_process_memory(child->pid,
          response.new_file_path,strlen(response.new_file_path)+1);
        params[1] = (reg_v) new_file_path;
        free(response.new_file_path);
      }
    }
    set_syscall_params(child);

    if (file_name != NULL) {
      free(file_name);
      free(abs_file_name);
    }
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
