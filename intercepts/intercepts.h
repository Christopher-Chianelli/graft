#ifndef CCHIANEL_GRAFT_INTERCEPTS_H
#define CCHIANEL_GRAFT_INTERCEPTS_H

#include "../graft.h"
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
