GCC := gcc
FLAGS := -Wall -g
SRCS := $(shell find $(SOURCEDIR) -name '*.c')
OUT := graft
GRAFT_DATA_DIR ?= $(HOME)/.local/share/graft

all: graft

clean:
	rm $(OUT)
	rm -rf $(GRAFT_DATA_DIR)

$(GRAFT_DATA_DIR):
	mkdir -m 700 -p $(GRAFT_DATA_DIR)

graft: $(GRAFT_DATA_DIR) $(SRCS) graft.h
	$(GCC) $(FLAGS) -DDEFAULT_GRAFT_DATA_DIR=\"$(GRAFT_DATA_DIR)\" -o $(OUT) $(SRCS)
