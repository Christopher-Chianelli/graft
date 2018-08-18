/*
 * file_manager.h - file interfaces for the graft program
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

#ifndef CCHIANEL_GRAFT_FILE_MANAGER_H

#define CCHIANEL_GRAFT_FILE_MANAGER_H

#include <stdlib.h>
#include <sys/types.h>

struct file_info {
	ino_t        d_ino;    /* 64-bit inode number */
    char           d_name[256]; /* Filename (null-terminated) */
};

extern void init_file_list_for_fd(unsigned int fd, const char *path);
extern void remove_file_list_for_fd(unsigned int fd);
extern struct vector *get_file_list_for_fd(unsigned int fd);
extern void add_file_to_fd(unsigned int fd, struct file_info *file);
extern void remove_file_from_fd(unsigned int fd, struct file_info *file);
extern void override_file_from_fd(unsigned int fd, struct file_info *old_file, struct file_info *new_file);
extern size_t get_entries_read_for_fd(unsigned int fd);
extern void set_entries_read_for_fd(unsigned int fd, size_t entries_read);

extern int is_dir(const char *dir_path);
extern int copy_file(const char *from_file, const char *to_file);
extern void depth_first_access_dir(const char *path, int (*action)(const char *, const char *, int));

#endif /* CCHIANEL_GRAFT_FILE_MANAGER_H */
