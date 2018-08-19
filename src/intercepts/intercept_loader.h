#ifndef CCHIANEL_GRAFT_INTERCEPT_LOADER_H
#define CCHIANEL_GRAFT_INTERCEPT_LOADER_H

#include <graft.h>

struct graft_intercept_manager {
	int syscall_intercept_functions_count;
	void (**syscall_intercept_functions)(struct graft_process_data *);
};

/**
 * Attemptes to load intercept from file. Returns pointer to handler, required for unloading. NULL On error.
 */
extern void *load_intercept_from_file(struct graft_intercept_manager *intercept_manager, const char *intercept_name, const char *intercept_file_path);

/**
 * Frees resources allocated to the intercept handler
 */
extern void unload_intercept(void *intercept_handler);

#endif //CCHIANEL_GRAFT_INTERCEPT_LOADER_H
