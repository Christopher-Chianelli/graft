/*
 * intercepts.h - interface for syscall handlers
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

#ifndef CCHIANEL_GRAFT_INTERCEPTS_H
#define CCHIANEL_GRAFT_INTERCEPTS_H

#include <graft.h>
#include <process/external_process_manipulator.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>

extern void set_syscall_params(struct graft_process_data *child);
extern void set_syscall_out(struct graft_process_data *child);

extern void graft_log_intercept(int syscall, ...);

// (0) sys_read fd buf count
extern void graft_intercept_read(struct graft_process_data *child);

// (1) sys_write fd buf count
extern void graft_intercept_write(struct graft_process_data *child);

// (2) sys_open filename flags mode
extern void graft_intercept_open(struct graft_process_data *child);
// (257) sys_openat dfd filename flags mode
extern void graft_intercept_open_at(struct graft_process_data *child);


#endif //CCHIANEL_GRAFT_INTERCEPTS_H
