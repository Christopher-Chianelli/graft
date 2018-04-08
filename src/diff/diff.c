#include <diff/diff.h>
#include <data_structures/matrix.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
