/*
 * open_intercepts.c - intercept grafted processes open syscalls
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

#include "intercepts.h"

// (2) sys_open filename flags mode
void graft_intercept_open(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    char *file_name;
    if (((char *)child->params[1]) != NULL) {
      file_name = read_string_from_process_memory(child, (void *) child->params[1]);
    }
    else {
      file_name = NULL;
    }
    int flags = (int) child->params[2];
    int mode = (int) child->params[3];
    char *abs_file_name;
    if (file_name != NULL) {
      abs_file_name = resolve_path_for_process(child, file_name);
    }
    else {
      abs_file_name = NULL;
    }

    graft_log_intercept((int) child->params[0], file_name, flags, mode);
    struct graft_open_file_request request;
    request.file_path = abs_file_name;
    request.flags = flags;
    request.mode = mode;

    struct graft_open_file_response response = handle_open_file_request(child, request);
    if (!response.is_allowed) {
      child->params[1] = (reg_v) NULL;
    }
    else {
      if (response.is_redirected) {
        //printf("Redirecting to %s\n", response.new_file_path);
        void *new_file_path = write_temp_to_process_memory(child,
          response.new_file_path,strlen(response.new_file_path)+1);
        child->params[1] = (reg_v) new_file_path;
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
    //printf("Open returned "
    //  "with %llu\n", child->syscall_out);
  }
}

// (257) sys_openat dfd filename flags mode
void graft_intercept_open_at(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    char *file_name;
    if (((char *)child->params[2]) != NULL) {
      file_name = read_string_from_process_memory(child, (void *) child->params[2]);
    }
    else {
      file_name = NULL;
    }
    int fd = (int) child->params[1];
    int flags = (int) child->params[3];
    int mode = (int) child->params[4];
    char *abs_file_name;

    graft_log_intercept((int) child->params[0], fd, file_name, flags, mode);
    if (file_name != NULL) {
      abs_file_name = resolve_path_for_process(child, file_name);
    }
    else {
      abs_file_name = NULL;
    }

    struct graft_open_file_request request;
    request.file_path = abs_file_name;
    request.flags = flags;
    request.mode = mode;

    struct graft_open_file_response response = handle_open_file_request(child, request);
    if (!response.is_allowed) {
      child->params[2] = (reg_v) NULL;
    }
    else {
      if (response.is_redirected) {
        //printf("Redirecting to %s\n", response.new_file_path);
        void *new_file_path = write_temp_to_process_memory(child,
          response.new_file_path,strlen(response.new_file_path)+1);
        child->params[2] = (reg_v) new_file_path;
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
    //printf("OpenAt returned "
    //  "with %llu\n", child->syscall_out);
  }
}
