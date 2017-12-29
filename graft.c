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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>

struct vector *child_processes;
struct vector *graft_monitored_files;
struct graft_file default_file_action;

static int is_executable(char *candidate)
{
	return (access(candidate, X_OK) == 0);
}

//return 1 iff there is a slash without a backslash behind it
//(i.e. a path of the form x/y where x does not end with a backslash)
static int is_local_file(char *file) {
  char *end = file + strlen(file);
  int last_was_slash = 0;
  while (end >= file) {
    switch (*end) {
      case '/':
          if (last_was_slash) {
            return 1;
          }
          last_was_slash = 1;
          break;

      case '\\':
          last_was_slash = 0;
          break;

      default:
          if (last_was_slash) {
            return 1;
          }
          break;
    }
    end--;
  }
  return 0;
}

static char *find_executable(char *program) {
  if (program[0] == '/' || is_local_file(program)) {
    return realpath(program,NULL);
  }
  else {
    char candidate[PATH_MAX];
	  const char *d;
    char *path = getenv("PATH");
    char *path_copy = malloc(strlen(path)+1);
    strcpy(path_copy,path);

	  while ((d = strsep(&path_copy, ":")) != NULL) {
		  if (snprintf(candidate, sizeof(candidate), "%s/%s", d,
		      program) >= (int)sizeof(candidate)) {
            continue;
      }
		  if (is_executable(candidate)) {
        return realpath(candidate, NULL);
		  }
    }
  }
  return NULL;
}

static int is_open_allowed(struct graft_open_file_request request, struct graft_file *file_action) {
  int user_permissions = (file_action->can_execute*01) | (file_action->can_write*02) | (file_action->can_read*04);
  int all_permissions = (user_permissions) | (user_permissions << 3) | (user_permissions << 6);

  if (file_action->can_read && ((request.flags & O_RDWR) == O_RDONLY)) {
    return 1;
  }
  else if (file_action->can_write && ((request.flags & O_RDWR) == O_WRONLY)) {
    if (request.flags & O_CREAT) {
      return (all_permissions & request.mode) == request.mode;
    }
    else {
      return 1;
    }
  }
  else if (file_action->can_read && file_action->can_write && ((request.flags & O_RDWR) == O_RDWR)){
    if (request.flags & O_CREAT) {
      return (all_permissions & request.mode) == request.mode;
    }
    else {
      return 1;
    }
  }
  else {
    return 0;
  }
}

struct graft_open_file_response handle_open_file_request(struct graft_open_file_request request) {
  struct graft_open_file_response response;
  struct graft_file *file_action = NULL;

  if (request.file_path == NULL) {
    response.is_redirected = 0;
    response.is_allowed = 1;
    response.new_file_path = request.file_path;
    return response;
  }

  for (int i = 0; i < vector_size(graft_monitored_files); i++) {
    struct graft_file *temp = (struct graft_file *) vector_get(graft_monitored_files, i);
    if (strprefix(request.file_path,temp->real_path)) {
      if (strlen(request.file_path) == strlen(temp->real_path)) {
        file_action = temp;
        break;
      }
      else if (temp->override_children && (file_action == NULL ||
        strlen(temp->real_path) > strlen(file_action->real_path))) {
          file_action = temp;
        }
    }
  }

  if (NULL == file_action) {
    file_action = &default_file_action;
  }

  if (!file_action->is_override) {
    response.is_redirected = 0;
    response.is_allowed = 1;
    response.new_file_path = request.file_path;
    return response;
  }

  response.is_redirected = file_action->is_redirected;
  response.is_allowed = is_open_allowed(request, file_action);
  if (response.is_redirected) {
    char *new_path = malloc(PATH_MAX);
    strcpy(new_path, file_action->new_path);
    char *end = new_path + strlen(new_path);
    strcpy(end, request.file_path + strlen(file_action->real_path));
    response.new_file_path = new_path;
  }
  else {
    response.new_file_path = request.file_path;
  }
  return response;
}

static void init(pid_t child) {
  child_processes = vector_init(sizeof(struct graft_process_data));
  graft_monitored_files = vector_init(sizeof(struct graft_file));

  struct graft_process_data child_process;
  child_process.pid = child;
  child_process.in_syscall = 1;
  getcwd(child_process.cwd, sizeof(child_process.cwd));
  vector_push(child_processes, &child_process);

  /*struct graft_file temp;
  temp.real_path = "/home/cchianel/code/graft";
  temp.new_path = "/home/cchianel/code";
  temp.is_override = 1;
  temp.is_redirected = 1;
  temp.override_children = 0;
  temp.can_write = 0;
  temp.can_read = 0;
  temp.can_execute = 0;
  vector_push(graft_monitored_files, &temp);*/

  default_file_action.real_path = NULL;
  default_file_action.is_override = 0;
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
    init(child);
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
