#include <limits.h>

#include <sys/user.h>
#include <sys/wait.h>

extern struct user_regs_struct regs;

#ifdef __x86_64__
typedef typeof(regs.rax) reg_v;
#elif defined __i386__
typedef typeof(regs.eax) reg_v;
#endif

reg_v params[8];
reg_v syscall_out;

struct graft_process_data {
  pid_t pid;
  int in_syscall;
  char cwd[PATH_MAX];
};

struct vector {
  size_t type_size;
  size_t vector_size;
  size_t array_size;
  void *data;
};

extern struct vector *child_processes;

extern void handle_syscall(struct graft_process_data *child);

extern struct vector *vector_init(size_t type_size);
extern void vector_free(struct vector *vector);
extern int vector_size(struct vector *vector);
extern void vector_push(struct vector *vector, void *data);
extern void vector_prepend(struct vector *vector, void *data);
extern void vector_insert(struct vector *vector, void *data, int index);
extern void vector_pop(struct vector *vector);
extern void vector_remove(struct vector *vector, int index);
extern void *vector_get(struct vector *vector, int index);

extern char *read_string_from_process_memory(pid_t process, void *addr);
extern void *read_from_process_memory(pid_t process, void *addr, size_t length);
extern void write_to_process_memory(pid_t process, void *src, void *dst, size_t length);
