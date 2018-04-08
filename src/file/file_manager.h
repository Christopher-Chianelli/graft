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

extern int copy_file(const char *from_file, const char *to_file);
extern void depth_first_access_dir(const char *path, int (*action)(const char *, const char *, int));

#endif /* CCHIANEL_GRAFT_FILE_MANAGER_H */
