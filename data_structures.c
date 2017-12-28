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

char *read_string_from_process_memory(pid_t process, void *addr) {
  size_t length = 1;
  long data;
  long *word = addr;

  int himagic = 0x80808080L;
  int lomagic = 0x01010101L;

  do {
    data = ptrace(PTRACE_PEEKDATA, process, word + length, NULL);
    if (((data - lomagic) & ~data & himagic) != 0) {
      char *data_ptr = ((char *) &data) + sizeof(long);
      int i;
      for (i = 0; *data_ptr; i++) {
        data_ptr--;
      }
      char *out = (char *) read_from_process_memory(process,addr,sizeof(long)*length + i);
      return out;
    }
    length++;
  } while (1);
  return NULL;
}

void *read_from_process_memory(pid_t process, void *addr, size_t length) {
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
    out[i] = ptrace(PTRACE_PEEKDATA, process, word + i, NULL);
  }

  char *end = (char *)(out + word_length + sizeof(long));
  for (int i = length % sizeof(long); i > 0; i--) {
    *(end-i) = '\0';
  }

  return (void *) out;
}

//TODO: FIX ME!
void write_to_process_memory(pid_t process, void *src, void *dst, size_t length) {
  size_t word_length = word_length = length/sizeof(long);

  long *target = (long *) dst;
  long *data = (long *) src;
  int i;

  for (i = 0; i < word_length; i++) {
    ptrace(PTRACE_POKEDATA, process, target + i, &(data[i]));
  }

  if (length % sizeof(long) != 0) {
    int diff = length % sizeof(long);
    long *orig = (long *) read_from_process_memory(process, target + i,
      sizeof(long));
    //TODO: Make modifiy only length % sizeof(long) bytes of orig
    *orig = data[i];
    ptrace(PTRACE_POKEDATA, process, target + i, orig);
    free(orig);
  }
}

char *resolve_path_for_process(struct graft_process_data *child, const char *path) {
  if (path[0] != '/') {
    char *out = malloc(PATH_MAX);
    strcpy(out, child->cwd);
    int cwd_length = strlen(child->cwd);
    out[cwd_length + 1] = '/';
    strcpy(out + cwd_length + 2, path);
    return realpath(path,out);
  }
  else {
    return realpath(path, NULL);
  }
}
