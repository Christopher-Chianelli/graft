#include <data_structures/vector.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
