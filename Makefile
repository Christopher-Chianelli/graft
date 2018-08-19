GCC := gcc
MK_ROOT := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
SOURCE_DIR := $(MK_ROOT)/src
FLAGS := -Wall -g -rdynamic -I$(SOURCE_DIR) -ldl
INTERCEPT_FLAGS = -Wall -g -fpic -I$(SOURCE_DIR) 
SRCS := $(shell find $(SOURCE_DIR) -name 'default' -prune -o -name '*.c' -print)
HEADERS := $(shell find $(SOURCE_DIR) -name 'default' -prune -o -name '*.h' -print)
OUT := graft
INTERCEPTS_SOURCE_DIR := $(SOURCE_DIR)/intercepts/default
INTERCEPTS_OUT_DIR := bin/intercepts
GRAFT_DATA_DIR ?= $(HOME)/.local/share/graft

all: graft intercepts

clean:
	rm $(OUT)
	rm -rf $(GRAFT_DATA_DIR)

$(GRAFT_DATA_DIR):
	mkdir -m 700 -p $(GRAFT_DATA_DIR)
	
$(INTERCEPTS_OUT_DIR)/*.o: $(INTERCEPTS_SOURCE_DIR)/ $(SRCS)
	$(GCC) -c $< -o $@ $(INTERCEPT_FLAGS)

$(INTERCEPTS_OUT_DIR)/*.so: $(INTERCEPTS_OUT_DIR)/*.o
	$(GCC) -o $@ $^ -shared
	
intercepts: $(SRCS) $(HEADERS) $(INTERCEPTS_SOURCE_DIR)/*.c
	mkdir -p $(INTERCEPTS_OUT_DIR);
	for src in `ls $(INTERCEPTS_SOURCE_DIR)`; do \
	    filename="$${src%.*}"; \
	    $(GCC) -c $(INTERCEPTS_SOURCE_DIR)/$$src -o $(INTERCEPTS_OUT_DIR)/"$$filename".o $(INTERCEPT_FLAGS); \
	    $(GCC) -o $(INTERCEPTS_OUT_DIR)/"$$filename".so $(INTERCEPTS_OUT_DIR)/"$$filename".o -shared; \
	    rm $(INTERCEPTS_OUT_DIR)/"$$filename".o; \
	done

graft: $(GRAFT_DATA_DIR) $(SRCS) $(HEADERS)
	$(GCC) $(FLAGS) -DDEFAULT_GRAFT_DATA_DIR=\"$(GRAFT_DATA_DIR)\" -o $(OUT) $(SRCS)
