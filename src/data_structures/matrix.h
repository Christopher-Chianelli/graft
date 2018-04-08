/*
 * matrix.h - matrix defines
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
#ifndef CCHIANEL_GRAFT_MATRIX_H
#define CCHIANEL_GRAFT_MATRIX_H

#define MATRIX(type) type *
#define MATRIX_INIT(m,rows,cols,type) (m = calloc((rows+1)*(cols+1), sizeof(type)))
#define MATRIX_GET(m,rows,cols,x,y) (*(m + (cols)*(y) + (x)))
#define MATRIX_SET(m,rows,cols,x,y,v) (MATRIX_GET(m,rows,cols,x,y) = (v))
#define MATRIX_FREE(m) free(m)

#endif /* CCHIANEL_GRAFT_MATRIX_H */
