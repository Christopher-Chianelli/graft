/*
 * graft.c - create a grafted process
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

#include <sys/ptrace.h>
#include <sys/types.h>

struct vector *child_processes;

static int is_there(char *candidate)
{
	return (access(candidate, X_OK) == 0);
}

static char *find_executable(char *program) {
  if (program[0] == '/') {
    return program;
  }
  else {
    char candidate[PATH_MAX];
	  const char *d;
    char *path = getenv("PATH");
    char *path_copy = malloc(strlen(path)+1);
    strcpy(path_copy,path);
	  int len;

	  while ((d = strsep(&path_copy, ":")) != NULL) {
		  if (snprintf(candidate, sizeof(candidate), "%s/%s", d,
		      program) >= (int)sizeof(candidate)) {
            continue;
      }
		  if (is_there(candidate)) {
			  len = strlen(candidate) + 1;
			  char *out = malloc(len);
			  strncpy(out, candidate, len);
        return out;
		  }
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  pid_t child;
  int status;
  int arg_offset = 1;

  child = fork();

  if(child == 0) {
    int my_args_length = argc - arg_offset + 1;
    char **my_args = calloc(my_args_length, sizeof(char *));
    for (int i = 0; i < my_args_length - 1; i++) {
      my_args[i] = argv[arg_offset+i];
    }
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    status = execv(find_executable(my_args[0]), my_args);
    return status;
  }
  else {
    child_processes = vector_init(sizeof(struct graft_process_data));
    struct graft_process_data child_process;
    child_process.pid = child;
    child_process.in_syscall = 1;
    getcwd(child_process.cwd, sizeof(child_process.cwd));
    vector_push(child_processes, &child_process);
    siginfo_t infop;
    while(1) {
      waitid(P_ALL, 0, &infop, WSTOPPED);
      struct graft_process_data *child;
      int i;
      for (i = 0; i < vector_size(child_processes); i++) {
        child = (struct graft_process_data *) vector_get(child_processes, i);
        if (child->pid == infop.si_pid) {
          break;
        }
      }
      if(WIFEXITED(infop.si_status)) {
        vector_remove(child_processes, i);
        if (vector_size(child_processes) == 0) {
          return WEXITSTATUS(infop.si_status);
        }
      }
      handle_syscall(child);
      ptrace(PTRACE_SYSCALL,
        child->pid, NULL, NULL);
    }
  }
  return 0;
}
