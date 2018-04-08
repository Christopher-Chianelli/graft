/*
 * vector.h - vector type definition
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

#ifndef CCHIANEL_GRAFT_VECTOR_H
#define CCHIANEL_GRAFT_VECTOR_H

#include <stdlib.h>

struct vector {
  size_t type_size;
  size_t vector_size;
  size_t array_size;
  void *data;
};

extern struct vector *vector_init(size_t type_size);
extern void vector_free(struct vector *vector);
extern int vector_size(struct vector *vector);
extern void vector_push(struct vector *vector, const void *data);
extern void vector_prepend(struct vector *vector, const void *data);
extern void vector_insert(struct vector *vector, const void *data, int index);
extern void vector_pop(struct vector *vector);
extern void vector_remove(struct vector *vector, int index);
extern void *vector_get(struct vector *vector, int index);
extern void vector_set(struct vector *vector, const void *data, int index);

#endif /* CCHIANEL_GRAFT_VECTOR_H */
