#include <intercepts/intercept_loader.h>

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef int (*Intercept_Init_Func)(struct graft_intercept_manager *);

void *load_intercept_from_file(struct graft_intercept_manager *intercept_manager, const char *intercept_name, const char *intercept_file_path) {
	char full_path[PATH_MAX];
	char *real_path = realpath(intercept_file_path, full_path);

	if (real_path != NULL) {
		// Attempt to open the plugin DSO
		    void* libhandle = dlopen(real_path, RTLD_NOW);
		    if (!libhandle) {
		        fprintf(stderr, "Error loading DSO: %s\n", dlerror());
		        return NULL;
		    }

		    // Attempt to find the init function and then call it
		    char init_func_name[256];
		    int init_func_size = snprintf(init_func_name, 256, "init_%s", intercept_name);

		    if (init_func_size >= 256) {
		    	fprintf(stderr, "intercept_name (%s) too long\n", intercept_name);
		    	return NULL;
		    }
		    // dlsym returns void*, but we obviously need to cast it to a function
		    // pointer to be able to call it. Since void* and function pointers are
		    // mutually inconvertible in the eyes of C99, and -pedantic complains about
		    // a plain cast, we cast through a pointer-sized integer.
		    Intercept_Init_Func init_func = (Intercept_Init_Func) (
		        (intptr_t) dlsym(libhandle, init_func_name));

		    if (init_func == NULL) {
		        printf("Error loading init function: %s\n", dlerror());
		        dlclose(libhandle);
		        return NULL;
		    }

		    int rc = init_func(intercept_manager);
		    if (rc < 0) {
		        fprintf(stderr, "Error: Plugin init function returned %d\n", rc);
		        dlclose(libhandle);
		        return NULL;
		    }

		    printf("Loaded plugin from: '%s'\n", real_path);
		    return libhandle;
	}
	else {
		fprintf(stderr, "Path %s too long\n", intercept_file_path);
		return NULL;
	}
}

void unload_intercept(void *intercept_handle){
	dlclose(intercept_handle);
}
