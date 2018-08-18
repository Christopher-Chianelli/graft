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
#include <intercepts/syscall_list.h>

#include <stdarg.h>

struct user_regs_struct regs;
// Note: linux system calls are listed here:
// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

#define MAX_VALID_SYSCALL (328)

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
	if (NULL != SYSCALL_NAMES[syscall]){
		return SYSCALL_NAMES[syscall];
	}
	else {
		return "Unknown System Call";
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
  case SYS_getdents:
    graft_intercept_getdents(child);
    break;
  default:
    graft_log_intercept((int) child->params[0]);
    break;
  }
  intercept_end(child);
}
