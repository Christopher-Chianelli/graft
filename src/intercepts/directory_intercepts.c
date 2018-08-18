#include <data_structures/vector.h>
#include <intercepts/intercepts.h>
#include <file/file_manager.h>
#include <process/external_process_manipulator.h>

#include <stdlib.h>
#include <sys/types.h>

struct linux_dirent {
    long           d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

struct linux_dirent64 {
    ino_t        d_ino;    /* 64-bit inode number */
    off_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

// SYS_getdents fd, struct linux_dirent buf count;
// returns number of bytes read, 0 for EOF, -1 on error
void graft_intercept_getdents(struct graft_process_data *child) {
  if(child->in_syscall == 0) {
    unsigned int fd = (unsigned int) child->params[1];
    size_t count = (size_t) child->params[3];
    char *buf = (char *) child->params[2];

    // We are highjacking this syscall so results are consistent with
    // our internal file system
    size_t entries_read = get_entries_read_for_fd(fd);
    // TODO
  }
  else { /* Syscall exit */
    // DO NOTHING
    //printf("Write returned "
    //  "with %llu\n", child->syscall_out);
  }
}
