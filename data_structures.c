/*
 * data_structures.c - data structures and functions for handling grafted processes
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

#include "graft.h"

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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define INTIAL_VECTOR_SIZE (16)
int (*file_access_action)(const char *, int);

struct vector *vector_init(size_t type_size) {
  struct vector *out = malloc(sizeof(struct vector));
  out->type_size = type_size;
  out->vector_size = 0;
  out->data = malloc(type_size * INTIAL_VECTOR_SIZE);
  out->array_size = INTIAL_VECTOR_SIZE;
  return out;
}

void vector_free(struct vector *vector) {
  free(vector->data);
  free(vector);
}

int vector_size(struct vector *vector) {
  return vector->vector_size;
}

void vector_push(struct vector *vector, const void *data) {
  vector_insert(vector,data,vector_size(vector));
}

void vector_prepend(struct vector *vector, const void *data) {
  vector_insert(vector,data,0);
}

void vector_insert(struct vector *vector, const void *data, int index) {
  if (vector->array_size < vector_size(vector) + 1) {
    vector->data = realloc(vector->data,
      vector->type_size * vector->array_size * 2);
    vector->array_size *= 2;
  }
  memmove(vector->data + (vector->type_size*(index + 1)),
      vector->data + (vector->type_size*index),
      vector_size(vector) - index);
  memcpy(vector->data + (vector->type_size*index), data, vector->type_size);
  vector->vector_size++;
}

void vector_pop(struct vector *vector) {
  vector_remove(vector,vector_size(vector)-1);
}

void vector_remove(struct vector *vector, int index) {
  memmove(vector->data + (vector->type_size*index),
      vector->data + (vector->type_size*(index+1)),
      vector_size(vector) - index);
  vector->vector_size--;
}

void *vector_get(struct vector *vector, int index) {
  return vector->data + (vector->type_size*index);
}

void vector_set(struct vector *vector, const void *data, int index) {
  if (index < vector_size(vector)) {
    memcpy(vector->data + (vector->type_size*index), data, vector->type_size);
  }
  else if (index == vector_size(vector)) {
    vector_push(vector, data);
  }
}

char *read_string_from_process_memory(struct graft_process_data *child, void *addr) {
  size_t length = 1;
  long data;
  long *word = addr;

  int himagic = 0x80808080L;
  int lomagic = 0x01010101L;

  do {
    data = ptrace(PTRACE_PEEKDATA, child->pid, word + length, NULL);
    if (((data - lomagic) & ~data & himagic) != 0) {
      return (char *) read_from_process_memory(child,addr,sizeof(long)*(length + 1));
    }
    length++;
  } while (1);
  return NULL;
}

void *read_from_process_memory(struct graft_process_data *child, void *addr, size_t length) {
  size_t word_length;

  if (length % sizeof(long) == 0) {
    word_length = length/sizeof(long);
  }
  else {
    word_length = length/sizeof(long) + 1;
  }

  long *word = addr;
  long *out = malloc(word_length*sizeof(long));

  for (int i = 0; i < word_length; i++) {
    out[i] = ptrace(PTRACE_PEEKDATA, child->pid, word + i, NULL);
  }

  char *end = (char *)(out + word_length + sizeof(long));
  for (int i = length % sizeof(long); i > 0; i--) {
    *(end-i) = '\0';
  }

  return (void *) out;
}

//TODO: FIX ME!
void write_to_process_memory(struct graft_process_data *child, void *src, void *dst, size_t length) {
  size_t word_length = word_length = length/sizeof(long);

  long *target = (long *) dst;
  long *data = (long *) src;
  int i;

  for (i = 0; i < word_length; i++) {
    ptrace(PTRACE_POKEDATA, child->pid, target + i, &(data[i]));
  }

  if (length % sizeof(long) != 0) {
    int diff = length % sizeof(long);
    long *orig = (long *) read_from_process_memory(child, target + i,
      sizeof(long));
    //TODO: Make modifiy only length % sizeof(long) bytes of orig
    *orig = data[i];
    ptrace(PTRACE_POKEDATA, child->pid, target + i, orig);
    free(orig);
  }
}

void *write_temp_to_process_memory(struct graft_process_data *child, void *src, size_t length) {
   char *stack_addr, *temp_addr;

   stack_addr = (char *) child->stack_p;
   /* Move further of red zone and make sure we have space for the file name */
   stack_addr -= RED_ZONE + length;
   temp_addr = stack_addr;

   /* Write new file in lower part of the stack */
   long *word = (long *) src;
   size_t word_length;

   if (length % sizeof(long) == 0) {
     word_length = length/sizeof(long);
   }
   else {
     word_length = length/sizeof(long) + 1;
   }

   for (int i = 0; i < word_length; i++) {
     ptrace(PTRACE_POKEDATA, child->pid, stack_addr, *word);
     stack_addr += sizeof(long);
     word++;
   }
   return temp_addr;
}

int strprefix(const char *query, const char *prefix)
{
    return strncmp(query, prefix, strlen(prefix)) == 0;
}

char *resolve_path_for_process(struct graft_process_data *child, const char *path) {
  if (path[0] != '/') {
    char *out = malloc(PATH_MAX);
    strcpy(out, child->cwd);
    int cwd_length = strlen(child->cwd);
    out[cwd_length] = '/';
    out[cwd_length+1] = '\0';
    strcpy(out + cwd_length + 1, path);
    char *returnval = realpath(out, NULL);
    if (returnval == NULL) {
      return out;
    }
    else {
      free(out);
      return returnval;
    }
  }
  else {
    char *returnval = realpath(path, NULL);
    if (returnval == NULL) {
      char *out = malloc(strlen(path) + 1);
      strcpy(out,path);
      return out;
    }
    else {
      return returnval;
    }
  }
}

#define MATRIX(type) type *
#define MATRIX_INIT(m,rows,cols,type) (m = calloc((rows+1)*(cols+1), sizeof(type)))
#define MATRIX_GET(m,rows,cols,x,y) (*(m + (cols)*(y) + (x)))
#define MATRIX_SET(m,rows,cols,x,y,v) (MATRIX_GET(m,rows,cols,x,y) = (v))
#define MATRIX_FREE(m) free(m)
#define MAX(x,y) ((x > y)? x : y)

typedef struct {int length; const char *pos;} LINE;

static void backtrack_for_line(MATRIX(int) lcs, int rows, int cols,
  struct vector *orig_lines, struct vector *new_lines, struct vector *out) {
    int x = vector_size(orig_lines);
    int y = vector_size(new_lines);
    while (x > 0 && y > 0) {
      LINE *orig_line = (LINE *) vector_get(orig_lines,x-1);
      LINE *new_line = (LINE *) vector_get(new_lines,y-1);
      if (orig_line->length == new_line->length && !memcmp(orig_line->pos, new_line->pos, orig_line->length)) {
        x--;
        y--;
        vector_insert(out,orig_line,0);
      }
      else if (MATRIX_GET(lcs,rows,cols,x,y-1) < MATRIX_GET(lcs,rows,cols,x-1,y)) {
        x--;
      }
      else {
        y--;
      }
    }
  }
static void get_diff_for_line_from_lcs(MATRIX(int) lengths, int rows, int cols,
  int orig_line_offset, int new_line_offset, struct vector *orig_lines, struct vector *new_lines, struct vector *lcs, struct vector *out) {
  LINE *orig_line;
  LINE *new_line;
  int x = vector_size(orig_lines);
  int y = vector_size(new_lines);
  while (vector_size(lcs) > 0) {
    LINE *last_common_line = (LINE *) vector_get(lcs,vector_size(lcs)-1);
    int i = x;
    int j = y;
    orig_line = (LINE *) vector_get(orig_lines,i-1);
    while (orig_line->length != last_common_line->length || memcmp(orig_line->pos, last_common_line->pos, orig_line->length)) {
      i--;
      orig_line = (LINE *) vector_get(orig_lines,i-1);
    }

    new_line = (LINE *) vector_get(new_lines,j-1);
    while (new_line->length != last_common_line->length || memcmp(new_line->pos, last_common_line->pos, new_line->length)) {
      j--;
      new_line = (LINE *) vector_get(new_lines,j-1);
    }
    //lines i+1..x from orig_lines been deleted
    //lines j+1..y from new_lines been added
    if (i != x || j != y) {
      char buf[40];
      sprintf(buf,"#%d,%d\n",i + orig_line_offset+1,j + new_line_offset+1);
      for (int k = 0; k < strlen(buf); k++) {
        vector_push(out,&(buf[k]));
      }
      for (int k = i + 1; k <= x; k++) {
        vector_push(out,"-");
        orig_line = (LINE *) vector_get(orig_lines,k-1);
        for (int m = 0; m < orig_line->length; m++) {
          vector_push(out, &(orig_line->pos[m]));
        }
        vector_push(out,"\n");
      }
      for (int k = j + 1; k <= y; k++) {
        vector_push(out,"+");
        new_line = (LINE *) vector_get(new_lines,k-1);
        for (int m = 0; m < new_line->length; m++) {
          vector_push(out, &(new_line->pos[m]));
        }
        vector_push(out,"\n");
      }
      x = i-1;
      y = j-1;
    }
    vector_pop(lcs);
  }

  //Lines 1..x of orig_lines been deleted
  //Lines 1..y or new_lines been added
  int index = 0;
  if (x != 0 || y != 0) {
    char buf[40];
    sprintf(buf,"#%d,%d\n",1 + orig_line_offset, 1 + new_line_offset);
    for (int k = 0; k < strlen(buf); k++) {
      vector_insert(out,&(buf[k]),index);
      index++;
    }
    for (int k = 1; k <= x; k++) {
      vector_insert(out,"-",index);
      index++;
      orig_line = (LINE *) vector_get(orig_lines,k-1);
      for (int m = 0; m < orig_line->length; m++) {
        vector_insert(out, &(orig_line->pos[m]),index);
        index++;
      }
      vector_insert(out,"\n",index);
      index++;
    }
    for (int k = 1; k <= y; k++) {
      vector_insert(out,"+",index);
      index++;
      new_line = (LINE *) vector_get(new_lines,k-1);
      for (int m = 0; m < new_line->length; m++) {
        vector_insert(out, &(new_line->pos[m]),index);
        index++;
      }
      vector_insert(out,"\n",index);
      index++;
    }
  }
}

struct vector *get_diff(const char *orig_str, int orig_length,
  const char *new_str, int new_length, enum diff_format format) {
    struct vector *diff = vector_init(sizeof(char));
    int orig_pos = 0;
    int new_pos = 0;
    int orig_line_num = 0;
    int new_line_num = 0;
    int rows, cols;
    const char *tmp1 = orig_str;
    const char *tmp2 = new_str;
    MATRIX(int) lengths;

    while (tmp1 - orig_str < orig_length && tmp2 - new_str < new_length && *tmp1 == *tmp2) {
      if (*tmp1 == '\n' && format == LINE_DIFF) {
        orig_line_num++;
        new_line_num++;
        orig_length -= tmp1 - orig_str;
        new_length -= tmp2 - new_str;
        orig_str = tmp1;
        new_str = tmp2;
      }
      else if (format == CHAR_DIFF) {
        orig_str++;
        new_str++;
        orig_pos++;
        new_pos++;
        orig_length--;
        new_length--;
      }
      tmp1++;
      tmp2++;
    }
    if (tmp1 - orig_str == orig_length && format == LINE_DIFF) {
      if (new_length >= orig_length && new_str[orig_length-1] == '\n') {
        new_length -= orig_length;
        new_str += orig_length;
      }
      orig_str += orig_length;
      orig_line_num++;
      orig_length = 0;
    }
    if (tmp2 - new_str == new_length && format == LINE_DIFF) {
      if (orig_length >= new_length && orig_str[new_length-1] == '\n') {
        orig_length -= new_length;
        orig_str += new_length;
      }
      new_str += new_length;
      new_line_num++;
      new_length = 0;
    }

    // TODO: FIX ME FOR LINE_DIFF
    while (orig_length > 0 && new_length > 0 &&
      *(orig_str + orig_length - 1) == *(new_str + new_length - 1)) {
        orig_length--;
        new_length--;
    }

    switch(format) {
      case LINE_DIFF:
        ; //EMPTY STATEMENT - C GRAMMER DOES NOT ALLOW DECLARATIONS AFTER LABEL
        struct vector *orig_line_pos = vector_init(sizeof(LINE));
        struct vector *new_line_pos = vector_init(sizeof(LINE));

        // First, get the line lengths/positions
        LINE temp;
        temp.length = 0;
        temp.pos = orig_str;

        while (orig_length > 0) {
          if (*orig_str == '\n') {
            vector_push(orig_line_pos, &temp);
            temp.length = 0;
            temp.pos = orig_str + 1;
          }
          else {
            temp.length++;
          }
          orig_str++;
          orig_length--;
        }
        if (temp.length != 0) {
          vector_push(orig_line_pos, &temp);
        }

        temp.length = 0;
        temp.pos = new_str;
        while (new_length > 0) {
          if (*new_str == '\n') {
            vector_push(new_line_pos, &temp);
            temp.length = 0;
            temp.pos = new_str + 1;
          }
          else {
            temp.length++;
          }
          new_str++;
          new_length--;
        }
        if (temp.length != 0) {
          vector_push(new_line_pos, &temp);
        }

        // Now use Longest common subsequence algorithm
        LINE *orig_line, *new_line;
        rows = vector_size(orig_line_pos) + 1;
        cols = vector_size(new_line_pos) + 1;
        MATRIX_INIT(lengths,rows,cols,int);
        for (int x = 1; x <= vector_size(orig_line_pos); x++) {
          for (int y = 1; y <= vector_size(new_line_pos); y++) {
            orig_line = (LINE *) vector_get(orig_line_pos,x-1);
            new_line = (LINE *) vector_get(new_line_pos,y-1);
            if (orig_line->length == new_line->length && !memcmp(orig_line->pos, new_line->pos, orig_line->length)) {
              MATRIX_SET(lengths,rows,cols,x,y,MATRIX_GET(lengths,rows,cols,x-1,y-1)+1);
            }
            else {
              MATRIX_SET(lengths,rows,cols,x,y,MAX(MATRIX_GET(lengths,rows,cols,x-1,y),
            MATRIX_GET(lengths,rows,cols,x,y-1)));
            }
          }
        }
        // LCS Matrix is filled
        struct vector *lcs = vector_init(sizeof(LINE));
        backtrack_for_line(lengths,rows,cols,orig_line_pos,new_line_pos,lcs);
        get_diff_for_line_from_lcs(lengths,rows,cols,orig_line_num,new_line_num,orig_line_pos,new_line_pos,lcs,diff);
        MATRIX_FREE(lengths);
        vector_free(orig_line_pos);
        vector_free(new_line_pos);
        vector_free(lcs);
        break;
      case CHAR_DIFF:
        // TODO
        rows = orig_length+1;
        cols = new_length+1;
        MATRIX_INIT(lengths,rows,cols,int);
        break;
    }
    return diff;
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
