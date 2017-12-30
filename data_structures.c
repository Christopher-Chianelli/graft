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

void vector_push(struct vector *vector, void *data) {
  vector_insert(vector,data,vector_size(vector));
}

void vector_prepend(struct vector *vector, void *data) {
  vector_insert(vector,data,0);
}

void vector_insert(struct vector *vector, void *data, int index) {
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

int copy_file(const char *from_file, const char *to_file) {
    printf("OKAY\n");
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
