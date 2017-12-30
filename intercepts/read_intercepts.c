#include "intercepts.h"

// (0) sys_read fd buf count
void graft_intercept_read(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    //Do Nothing
  }
  else { /* Syscall exit */
    if (child->syscall_out > 0) {
      char *buf = (char *) read_from_process_memory(child,
      (void *) child->params[2],
      (int) child->syscall_out);
      graft_log_intercept((int) child->params[0], (int) (child->params[1]), buf,
        (int) child->syscall_out);
      free(buf);
    }
    else {
      graft_log_intercept((int) child->params[0], (int) (child->params[1]), "#EOF#",
        5);
    }
  }
}
