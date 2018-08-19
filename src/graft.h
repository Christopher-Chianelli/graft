/*
 * graft.h - interfaces for the graft program
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

#ifndef CCHIANEL_GRAFT_H
#define CCHIANEL_GRAFT_H


#include <data_structures/vector.h>

#include <limits.h>

#include <sys/user.h>
#include <sys/wait.h>

extern struct user_regs_struct regs;

#ifdef __x86_64__
typedef typeof(regs.rax) reg_v;
#define RED_ZONE (128)
#elif defined __i386__
typedef typeof(regs.eax) reg_v;
#define RED_ZONE (0)
#endif

#define ALL_OPEN_FLAGS (O_RDONLY | O_WRONLY | O_RDWR)

struct graft_file {
  // The path this rule represent
  const char *real_path;

  // The redirected file path
  char *new_path;

  // If is_override is set, make all syscalls use new_path instead of real_path
  // If override_children is set, also override syscalls for children of this directory
  //If flatten_children is set, put all desendants into new_path, renaming the file to keep path info
  char is_override, override_children, flatten_children;

  // If redirect_on_x is set, redirect on all x operation
  char redirect_on_read, redirect_on_write, redirect_on_execute;

  // If copy_on_x is set, copy the file to new_path if it does not exist
  char copy_on_read, copy_on_write, copy_on_execute;

  // If can_x is set, allow x operation
  char can_read, can_write, can_execute;
};

struct graft_open_file_request {
  char *file_path;
  int flags;
  int mode;
};

struct graft_open_file_response {
  int is_redirected;
  int is_allowed;
  char *new_file_path;
};

struct graft_process_data {
  pid_t pid;
  int in_syscall;
  reg_v orig_syscall;
  reg_v params[8];
  reg_v syscall_out;
  reg_v stack_p;
  struct graft_file default_file_action;
  char cwd[PATH_MAX];
};

struct graft_config {
	const char *default_intercept_directory;
};

extern const char *graft_data_dir;
extern struct vector *child_processes;

extern void graft_setup_child(pid_t pid, struct graft_process_data *parent);
extern void graft_cleanup_child(struct graft_process_data *child, int i);
extern struct graft_open_file_response handle_open_file_request(struct graft_process_data *child, struct graft_open_file_request request);

extern void handle_syscall(struct graft_process_data *child);

extern int strprefix(const char *query, const char *prefix);
extern char *resolve_path_for_process(struct graft_process_data *child, const char *path);

#endif /* CCHIANEL_GRAFT_H */
