#include <file/file_manager.h>
#include <data_structures/vector.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <dirent.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <copyfile.h>
#else
#include <sys/sendfile.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

struct fd_file_list {
  unsigned int fd;
  size_t entries_read;
  const char *path;
  struct vector *file_list;
};

struct vector *fd_file_list_list = NULL;

void init_file_list_for_fd(unsigned int fd, const char *path) {
  if (fd_file_list_list == NULL) {
      fd_file_list_list = vector_init(sizeof(struct fd_file_list));
  }
  DIR *dir = opendir(path);
  struct dirent *entry;

  struct vector *file_list = vector_init(sizeof(struct file_info));
  // TODO: Check for errors
  while ((entry = readdir(dir)) != NULL) {
    struct file_info info;
    info.d_ino = entry->d_ino;
    strcpy(entry->d_name, info.d_name);
    vector_push(file_list, &info);
  }
  closedir(dir);

  struct fd_file_list to_add;
  to_add.fd = fd;
  to_add.entries_read = 0;
  to_add.path = path;
  to_add.file_list = file_list;
  vector_push(fd_file_list_list, &to_add);
}

void remove_file_list_for_fd(unsigned int fd) {
  for (int i = 0; i < vector_size(fd_file_list_list); i++) {
    struct fd_file_list *fd_file_list = vector_get(fd_file_list_list,i);
    if (fd_file_list->fd == fd) {
      vector_free(fd_file_list->file_list);
      vector_remove(fd_file_list_list, i);
      return;
    }
  }
}

struct vector *get_file_list_for_fd(unsigned int fd) {
  for (int i = 0; i < vector_size(fd_file_list_list); i++) {
    struct fd_file_list *fd_file_list = vector_get(fd_file_list_list,i);
    if (fd_file_list->fd == fd) {
      return fd_file_list->file_list;
    }
  }
  return NULL;
}

size_t get_entries_read_for_fd(unsigned int fd) {
  for (int i = 0; i < vector_size(fd_file_list_list); i++) {
    struct fd_file_list *fd_file_list = vector_get(fd_file_list_list,i);
    if (fd_file_list->fd == fd) {
      return fd_file_list->entries_read;
    }
  }
  return -1;
}

void set_entries_read_for_fd(unsigned int fd, size_t entries_read) {
  for (int i = 0; i < vector_size(fd_file_list_list); i++) {
    struct fd_file_list *fd_file_list = vector_get(fd_file_list_list,i);
    if (fd_file_list->fd == fd) {
      fd_file_list->entries_read = entries_read;
      return;
    }
  }
}

void add_file_to_fd(unsigned int fd, struct file_info *file) {
  vector_push(get_file_list_for_fd(fd), &file);
}

void remove_file_from_fd(unsigned int fd, struct file_info *file) {
  struct vector *fd_file_list = get_file_list_for_fd(fd);
  for (int i = 0; i < vector_size(fd_file_list); i++) {
    struct file_info *fd_file = vector_get(fd_file_list, i);
    if (fd_file->d_ino == file->d_ino) {
      vector_remove(fd_file_list, i);
      return;
    }
  }
}

void override_file_from_fd(unsigned int fd, struct file_info *old_file, struct file_info *new_file) {
  struct vector *fd_file_list = get_file_list_for_fd(fd);
  for (int i = 0; i < vector_size(fd_file_list); i++) {
    struct file_info *fd_file = vector_get(fd_file_list, i);
    if (fd_file->d_ino == old_file->d_ino) {
      vector_set(fd_file_list, new_file, i);
      return;
    }
  }
}

int copy_file(const char *from_file, const char *to_file) {
    int input, output;
    if ((input = open(from_file, O_RDONLY)) == -1)
    {
        return -1;
    }
    if ((output = creat(to_file, 0660)) == -1)
    {
        close(input);
        return -1;
    }

    //Here we use kernel-space copying for performance reasons
    #if defined(__APPLE__) || defined(__FreeBSD__)
    //fcopyfile works on FreeBSD and OS X 10.5+
        int result = fcopyfile(input, output, 0, COPYFILE_ALL);
    #else
    //sendfile will work with non-socket output (i.e. regular file) on Linux 2.6.33+
        struct stat fileinfo = {0};
        fstat(input, &fileinfo);
        off_t offset=0, total_sent=0;
        ssize_t sent;

        do {
          sent = sendfile(output, input, &offset, fileinfo.st_size-total_sent);
        } while(sent > -1 && (total_sent += sent) < fileinfo.st_size);
        int result = 1;
    #endif

    close(input);
    close(output);

    return result;
}

int is_dir(const char *dir_path)
{
    struct stat sb;

    if (stat(dir_path, &sb) == 0 && S_ISDIR(sb.st_mode))
        return 1;
    else
        return 0;
}

void depth_first_access_dir(const char *path, int (*action)(const char *, const char *, int)) {
  DIR *directory = opendir(path);
  struct dirent *next_file;
  char filepath[PATH_MAX];

  while ( (next_file = readdir(directory)) != NULL )
  {
      sprintf(filepath, "%s/%s", path, next_file->d_name);

      //skip parent and current directory
      if ((strcmp(next_file->d_name,"..") == 0) ||
          (strcmp(next_file->d_name,"." ) == 0) )
      {
          continue;
      }

      if (is_dir(filepath))
      {
          depth_first_access_dir(filepath, action);
      }
      else {
        action(path,filepath,0);
      }
  }
  closedir(directory);
  action(path,path,1);
}
