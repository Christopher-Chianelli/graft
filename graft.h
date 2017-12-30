#ifndef CCHIANEL_GRAFT_H
#define CCHIANEL_GRAFT_H
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

struct graft_process_data {
  pid_t pid;
  int in_syscall;
  reg_v params[8];
  reg_v syscall_out;
  reg_v stack_p;
  char cwd[PATH_MAX];
};

struct graft_file {
  const char *real_path;
  const char *new_path;
  char is_override, override_children;
  char is_redirected, flatten_children;
  char can_read, can_write, can_execute;
};
extern struct graft_file default_file_action;

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

struct vector {
  size_t type_size;
  size_t vector_size;
  size_t array_size;
  void *data;
};

extern const char *graft_data_dir;
extern struct vector *child_processes;

extern struct graft_open_file_response handle_open_file_request(struct graft_open_file_request request);

extern void handle_syscall(struct graft_process_data *child);
extern int copy_file(const char *from_file, const char *to_file);

extern struct vector *vector_init(size_t type_size);
extern void vector_free(struct vector *vector);
extern int vector_size(struct vector *vector);
extern void vector_push(struct vector *vector, void *data);
extern void vector_prepend(struct vector *vector, void *data);
extern void vector_insert(struct vector *vector, void *data, int index);
extern void vector_pop(struct vector *vector);
extern void vector_remove(struct vector *vector, int index);
extern void *vector_get(struct vector *vector, int index);

extern int strprefix(const char *query, const char *prefix);
extern char *resolve_path_for_process(struct graft_process_data *child, const char *path);

extern char *read_string_from_process_memory(struct graft_process_data *child, void *addr);
extern void *read_from_process_memory(struct graft_process_data *child, void *addr, size_t length);
extern void write_to_process_memory(struct graft_process_data *child, void *src, void *dst, size_t length);
extern void *write_temp_to_process_memory(struct graft_process_data *child, void *src, size_t length);

#endif /* CCHIANEL_GRAFT_H */
