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
#elif defined __i386__
typedef typeof(regs.eax) reg_v;
#endif

reg_v params[8];
reg_v syscall_out;

struct graft_process_data {
  pid_t pid;
  int in_syscall;
  char cwd[PATH_MAX];
};

struct vector {
  size_t type_size;
  size_t vector_size;
  size_t array_size;
  void *data;
};

extern struct vector *child_processes;

extern void handle_syscall(struct graft_process_data *child);

extern struct vector *vector_init(size_t type_size);
extern void vector_free(struct vector *vector);
extern int vector_size(struct vector *vector);
extern void vector_push(struct vector *vector, void *data);
extern void vector_prepend(struct vector *vector, void *data);
extern void vector_insert(struct vector *vector, void *data, int index);
extern void vector_pop(struct vector *vector);
extern void vector_remove(struct vector *vector, int index);
extern void *vector_get(struct vector *vector, int index);

extern char *resolve_path_for_process(struct graft_process_data *child, const char *path);

extern char *read_string_from_process_memory(pid_t process, void *addr);
extern void *read_from_process_memory(pid_t process, void *addr, size_t length);
extern void write_to_process_memory(pid_t process, void *src, void *dst, size_t length);

#endif /* CCHIANEL_GRAFT_H */
