/*
 * external_process_manipulator.h - interfaces for manipulating an external process
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

#ifndef CCHIANEL_GRAFT_EXTERNAL_PROCESS_MANAGER
#define CCHIANEL_GRAFT_EXTERNAL_PROCESS_MANAGER

#include <graft.h>

extern char *read_string_from_process_memory(struct graft_process_data *child, void *addr);
extern void *read_from_process_memory(struct graft_process_data *child, void *addr, size_t length);
extern void write_to_process_memory(struct graft_process_data *child, void *src, void *dst, size_t length);
extern void *write_temp_to_process_memory(struct graft_process_data *child, void *src, size_t length);

#endif /* CCHIANEL_GRAFT_EXTERNAL_PROCESS_MANAGER */
