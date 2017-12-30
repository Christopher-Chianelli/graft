#include "intercepts.h"

// (1) sys_write fd buf count
void graft_intercept_write(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    unsigned int fd = (unsigned int) child->params[1];
    size_t count = (size_t) child->params[3];
    char *buf = (char *) read_from_process_memory(child,
      (void *) child->params[2],
      count);
    graft_log_intercept((int) child->params[0], fd, buf,
      (int) count);
    free(buf);
  }
  else { /* Syscall exit */
    // DO NOTHING
    //printf("Write returned "
    //  "with %llu\n", child->syscall_out);
  }
}
