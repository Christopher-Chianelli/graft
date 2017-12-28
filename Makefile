GCC := gcc
FLAGS := -Wall
SRCS := graft.c intercept_syscall.c data_structures.c
OUT := graft

all: graft

clean:
	rm $(OUT)

graft: $(SRCS)
	$(GCC) $(FLAGS) -o $(OUT) $(SRCS)