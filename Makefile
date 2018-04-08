GCC := gcc
MK_ROOT := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
SOURCE_DIR := $(MK_ROOT)/src
FLAGS := -Wall -g -I$(SOURCE_DIR)
SRCS := $(shell find $(SOURCE_DIR) -name '*.c')
HEADERS := $(shell find $(SOURCE_DIR) -name '*.h')
OUT := graft
GRAFT_DATA_DIR ?= $(HOME)/.local/share/graft

all: graft

clean:
	rm $(OUT)
	rm -rf $(GRAFT_DATA_DIR)

$(GRAFT_DATA_DIR):
	mkdir -m 700 -p $(GRAFT_DATA_DIR)

graft: $(GRAFT_DATA_DIR) $(SRCS) $(HEADERS)
	$(GCC) $(FLAGS) -DDEFAULT_GRAFT_DATA_DIR=\"$(GRAFT_DATA_DIR)\" -o $(OUT) $(SRCS)
