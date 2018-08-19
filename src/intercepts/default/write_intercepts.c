/*
 * write_intercepts.c - intercept grafted processes write syscalls
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
#include <intercepts/intercepts.h>
#include <intercepts/intercept_loader.h>

#include <sys/syscall.h>

// (1) sys_write fd buf count
static void graft_intercept_write(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    unsigned int fd = (unsigned int) child->params[1];
    size_t count = (size_t) child->params[3];
    if (count <= 80) {
      char *buf = (char *) read_from_process_memory(child,
        (void *) child->params[2],
        count);
      graft_log_intercept((int) child->params[0], fd, buf,
        (int) count);
      free(buf);
    }
    else {
        graft_log_intercept((int) child->params[0], fd, "Data to long to display",
          23);
    }
  }
  else { /* Syscall exit */
    // DO NOTHING
    //printf("Write returned "
    //  "with %llu\n", child->syscall_out);
  }
}

int init_write_intercepts(struct graft_intercept_manager *graft_intercept_manager) {
    #ifdef SYS_write
	graft_intercept_manager->syscall_intercept_functions[SYS_write] = &graft_intercept_write;
    #endif
	return 0;
}

