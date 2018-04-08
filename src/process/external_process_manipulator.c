#include <graft.h>
#include <process/external_process_manipulator.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>

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
