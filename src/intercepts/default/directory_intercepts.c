#include <data_structures/vector.h>
#include <intercepts/intercepts.h>
#include <intercepts/intercept_loader.h>
#include <file/file_manager.h>
#include <process/external_process_manipulator.h>

#include <stdlib.h>
#include <sys/types.h>

#include <sys/syscall.h>

struct my_linux_dirent {
    long           d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

struct my_linux_dirent64 {
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
    skip_syscall(child);
  }
  else { /* Syscall exit */
	    // We are highjacking this syscall so results are consistent with
	    // our internal file system
	    unsigned int fd = (unsigned int) child->params[1];
	    size_t count = (size_t) child->params[3];
	    char *process_buf = (char *) child->params[2];

	    size_t entries_read = get_entries_read_for_fd(fd);
	    struct vector *file_list_for_fd = get_file_list_for_fd(fd);
	    size_t bytes_read = 0;
	    size_t i;

	    if (NULL == file_list_for_fd || entries_read == vector_size(file_list_for_fd)) {
	    	child->syscall_out = 0;
	    	set_syscall_out(child);
	    	graft_log_intercept(SYS_getdents,"EOF");
	    }
	    else {
		  char *out_buf = malloc(count);
		  char *log_out = malloc(count);
	      for (i = entries_read; i < vector_size(file_list_for_fd) && bytes_read < count; i++) {
	    	struct file_info *file_info = vector_get(file_list_for_fd, i);
	    	printf("DEBUG: %s\n", file_info->d_name);
	    	struct my_linux_dirent *direct = (void *) (out_buf + bytes_read);
	    	size_t dir_name_length = strlen(file_info->d_name) + 1;

	    	if ((direct->d_name - out_buf) + dir_name_length > count) {
	    		break;
	    	}

	    	direct->d_ino = file_info->d_ino;
	    	direct->d_off = (direct->d_name - out_buf) + dir_name_length;
	    	direct->d_reclen = (direct->d_name - (char *) direct)+ dir_name_length;
	    	strcpy(direct->d_name, file_info->d_name);
	    	bytes_read += direct->d_reclen;
	    	strcat(log_out, file_info->d_name);
	    	strcat(log_out, ",");
	      }
	      set_entries_read_for_fd(fd, entries_read + i);
	      write_to_process_memory(child, out_buf, process_buf, count);
	      child->syscall_out = bytes_read;
	      set_syscall_out(child);
	      free(out_buf);
	      graft_log_intercept(SYS_getdents, log_out);
	      free(log_out);
	    }
  }
}

int init_directory_intercepts(struct graft_intercept_manager *graft_intercept_manager) {
    #ifdef SYS_getdents
	graft_intercept_manager->syscall_intercept_functions[SYS_getdents] = &graft_intercept_getdents;
    #endif
	return 0;
}
