#include <file/file_manager.h>

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

static int is_dir(const char *dir_path)
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
