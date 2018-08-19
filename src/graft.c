/*
 * graft.c - create a grafted process
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

#include <graft.h>
#include <intercepts/intercepts.h>
#include <file/file_manager.h>
#include <diff/diff.h>

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>


struct vector *child_processes;
struct vector *graft_monitored_files;
struct graft_file default_file_action;
struct graft_config graft_config;
const char *graft_data_dir = DEFAULT_GRAFT_DATA_DIR;

int strprefix(const char *query, const char *prefix)
{
    return strncmp(query, prefix, strlen(prefix)) == 0;
}

char *resolve_path_for_process(struct graft_process_data *child, const char *path) {
  if (path[0] != '/') {
    char *out = malloc(PATH_MAX);
    strcpy(out, child->cwd);
    int cwd_length = strlen(child->cwd);
    out[cwd_length] = '/';
    out[cwd_length+1] = '\0';
    strcpy(out + cwd_length + 1, path);
    char *returnval = realpath(out, NULL);
    if (returnval == NULL) {
      return out;
    }
    else {
      free(out);
      return returnval;
    }
  }
  else {
    char *returnval = realpath(path, NULL);
    if (returnval == NULL) {
      char *out = malloc(strlen(path) + 1);
      strcpy(out,path);
      return out;
    }
    else {
      return returnval;
    }
  }
}

static int is_executable(char *candidate)
{
	return (access(candidate, X_OK) == 0);
}

//return 1 iff there is a slash without a backslash behind it
//(i.e. a path of the form x/y where x does not end with a backslash)
static int is_local_file(char *file) {
  char *end = file + strlen(file);
  int last_was_slash = 0;
  while (end >= file) {
    switch (*end) {
      case '/':
          if (last_was_slash) {
            return 1;
          }
          last_was_slash = 1;
          break;

      case '\\':
          last_was_slash = 0;
          break;

      default:
          if (last_was_slash) {
            return 1;
          }
          break;
    }
    end--;
  }
  return 0;
}

static char *find_executable(char *program) {
  if (program[0] == '/' || is_local_file(program)) {
    return realpath(program,NULL);
  }
  else {
    char candidate[PATH_MAX];
	  const char *d;
    char *path = getenv("PATH");
    char *path_copy = malloc(strlen(path)+1);
    strcpy(path_copy,path);

	  while ((d = strsep(&path_copy, ":")) != NULL) {
		  if (snprintf(candidate, sizeof(candidate), "%s/%s", d,
		      program) >= (int)sizeof(candidate)) {
            continue;
      }
		  if (is_executable(candidate)) {
        return realpath(candidate, NULL);
		  }
    }
  }
  return NULL;
}

static int is_open_allowed(struct graft_open_file_request request, struct graft_file *file_action) {
  int user_permissions = (file_action->can_execute*01) | (file_action->can_write*02) | (file_action->can_read*04);
  int all_permissions = (user_permissions) | (user_permissions << 3) | (user_permissions << 6);

  if (file_action->can_read && ((request.flags & ALL_OPEN_FLAGS) == O_RDONLY)) {
    return 1;
  }
  else if (file_action->can_write && ((request.flags & ALL_OPEN_FLAGS) == O_WRONLY)) {
    if (request.flags & O_CREAT) {
      return (all_permissions & request.mode) == request.mode;
    }
    else {
      return 1;
    }
  }
  else if (file_action->can_read && file_action->can_write && ((request.flags & ALL_OPEN_FLAGS) == O_RDWR)){
    if (request.flags & O_CREAT) {
      return (all_permissions & request.mode) == request.mode;
    }
    else {
      return 1;
    }
  }
  else {
    return 0;
  }
}

static int combine_bits(int r, int w, int e) {
	return (r << 2) | (w << 1) | e;
}

static int any_bit_match(int my_bits, int flags) {
	int real_flags = 0;
	if ((flags & ALL_OPEN_FLAGS) == O_RDONLY) {
		real_flags = 4;
	}
	else if ((flags & ALL_OPEN_FLAGS) == O_WRONLY) {
		real_flags = 2;
	}
	else if ((flags & ALL_OPEN_FLAGS) == O_RDWR) {
		real_flags = 6;
	}

	return my_bits & real_flags;
}

static char *get_redirected_file_path(char *file_path, struct graft_file *file_action) {
	char *new_path = malloc(PATH_MAX);
	strcpy(new_path, file_action->new_path);
	char *end = new_path + strlen(new_path);

	if (file_action->flatten_children) {
		char *path_rest = file_path + strlen(file_action->real_path);
		printf("%s\n", path_rest);
		if (*path_rest != '\0') {
			*end = '/';
			end++;
		}
		while (*path_rest != '\0') {
			switch (*path_rest) {
				case '/':
					*end = '>';
					end++;
					break;
				case '>':
					*end = '\\';
					end++;
					*end = '>';
					end++;
					break;

				case '\\':
					*end = '\\';
					end++;
					*end = '\\';
					end++;
					break;

				default:
					*end = *path_rest;
					end++;
					break;
			}
			path_rest++;
		}
		*end = '\0';
	}
	else {
		strcpy(end, file_path + strlen(file_action->real_path));
	}
	return new_path;
}

static char *get_orig_file_path(const char *prefix, const char *path) {
	char *out = malloc(PATH_MAX);
	//strcpy(out,prefix);
	char *end = out;//+ strlen(prefix);
	const char *path_rest = path + strlen(prefix);

	while (*path_rest != '\0') {
		switch (*path_rest) {
			case '>':
				*end = '/';
				break;

			case '\\':
				path_rest++;
				*end = *path_rest;
				break;

			default:
				*end = *path_rest;
				break;
		}
		end++;
		path_rest++;
	}
	*end = '\0';
	return out;
}

struct graft_open_file_response handle_open_file_request(struct graft_process_data *child, struct graft_open_file_request request) {
  struct graft_open_file_response response;
  struct graft_file *file_action = NULL;

  if (request.file_path == NULL) {
    response.is_redirected = 0;
    response.is_allowed = 1;
    response.new_file_path = request.file_path;
    return response;
  }

  for (int i = 0; i < vector_size(graft_monitored_files); i++) {
    struct graft_file *temp = (struct graft_file *) vector_get(graft_monitored_files, i);
    if (strprefix(request.file_path,temp->real_path)) {
      if (strlen(request.file_path) == strlen(temp->real_path)) {
        file_action = temp;
        break;
      }
      else if (temp->override_children && (file_action == NULL ||
        strlen(temp->real_path) > strlen(file_action->real_path))) {
          file_action = temp;
        }
    }
  }

  if (NULL == file_action) {
    file_action = &(child->default_file_action);
  }

  if (!file_action->is_override) {
    response.is_redirected = 0;
    response.is_allowed = 1;
    response.new_file_path = request.file_path;
    return response;
  }

  response.is_redirected = 0;
  response.is_allowed = is_open_allowed(request, file_action);
  if (response.is_allowed
		&& any_bit_match(combine_bits(file_action->redirect_on_read,
			file_action->redirect_on_write,file_action->redirect_on_execute),
		  request.flags)) {
		response.is_redirected = 1;
    response.new_file_path = get_redirected_file_path(request.file_path, file_action);
		// TODO: Make a function to make sure we haven't already created a file
		if (any_bit_match(combine_bits(file_action->copy_on_read,
			file_action->copy_on_write,file_action->copy_on_execute),
		  request.flags) && access(request.file_path, F_OK) == 0 && access(response.new_file_path, F_OK) == -1) {
			copy_file(request.file_path,response.new_file_path);
		}
  }
  else {
    response.new_file_path = request.file_path;
  }
  return response;
}

void graft_setup_child(pid_t child, struct graft_process_data *parent) {
  struct graft_process_data child_process;
  child_process.pid = child;
  child_process.in_syscall = 1;
  getcwd(child_process.cwd, sizeof(child_process.cwd));

	char *new_path = malloc(PATH_MAX);
	strcpy(new_path, graft_data_dir);
	sprintf(new_path + strlen(graft_data_dir), "/%u", child);
	mkdir(new_path, 0700);

  child_process.default_file_action.real_path = "/";
	child_process.default_file_action.new_path = new_path;

  child_process.default_file_action.is_override = 1;
	child_process.default_file_action.override_children = 1;
	child_process.default_file_action.flatten_children = 1;

	child_process.default_file_action.redirect_on_read = 0;
	child_process.default_file_action.redirect_on_write = 1;
	child_process.default_file_action.redirect_on_execute = 0;

	child_process.default_file_action.copy_on_read = 0;
	child_process.default_file_action.copy_on_write = 1;
	child_process.default_file_action.copy_on_execute = 0;

  child_process.default_file_action.can_write = 1;
  child_process.default_file_action.can_read = 1;
  child_process.default_file_action.can_execute = 1;

	vector_push(child_processes, &child_process);
}

static struct vector *file_diff(const char *orig_file, const char *new_file, int is_binary) {
	FILE *orig_fp, *new_fp;

	orig_fp = fopen(orig_file, "r");
	new_fp = fopen(new_file, "r");
	struct vector *orig_file_content = vector_init(sizeof(char));
	struct vector *new_file_content = vector_init(sizeof(char));
	char data;

	if (orig_fp != NULL) {
		while ((data = getc(orig_fp)) != EOF) {
			vector_push(orig_file_content, &data);
		}
		fclose(orig_fp);
	}

	if (new_fp != NULL) {
		while ((data = getc(new_fp)) != EOF) {
			vector_push(new_file_content, &data);
		}
		fclose(new_fp);
	}

	char *orig_file_data = (char *) vector_get(orig_file_content, 0);
	char *new_file_data = (char *) vector_get(new_file_content, 0);
	int orig_file_length = vector_size(orig_file_content);
	int new_file_length = vector_size(new_file_content);

	if (is_binary) {
		struct vector *diff = get_diff(orig_file_data, orig_file_length, new_file_data, new_file_length, CHAR_DIFF);
		vector_free(orig_file_content);
		vector_free(new_file_content);
		return diff;
	}
	else {
		struct vector *diff = get_diff(orig_file_data, orig_file_length, new_file_data, new_file_length, LINE_DIFF);
		vector_free(orig_file_content);
		vector_free(new_file_content);
		return diff;
	}
}

static int graft_on_file_cleanup(const char *prefix, const char *path, int is_dir) {
	if (is_dir) {
		if(remove(path) < 0)
    {
        perror("remove");
        return -1;
    }
		return 0;
	}
	else {
		char *orig_path = get_orig_file_path(prefix,path);
		struct vector *diff = file_diff(orig_path,path,0);
		printf("M %s:\n", orig_path);
		for (int i = 0; i < vector_size(diff); i++) {
			putchar(*((char *) vector_get(diff,i)));
		}
		vector_free(diff);
		if(remove(path) < 0)
    {
        perror("remove");
        return -1;
    }
		return 0;
	}
}

void graft_cleanup_child(struct graft_process_data *child, int i) {
	if (i < 0) {
		for (i = 0; i < vector_size(child_processes); i++) {
			struct graft_process_data *temp = (struct graft_process_data *) vector_get(child_processes, i);
			if (child->pid == temp->pid) {
				break;
			}
		}
	}

	depth_first_access_dir(child->default_file_action.new_path, &graft_on_file_cleanup);
	free(child->default_file_action.new_path);
	vector_remove(child_processes, i);
}

static void load_config() {
	graft_config.default_intercept_directory = "bin/intercepts";
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s program\n", argv[0]);
		return 1;
	}

  pid_t child;
  int status;
  int arg_offset = 1;

  child = fork();

  if(child == 0) {
    int my_args_length = argc - arg_offset + 1;
    char **my_args = calloc(my_args_length, sizeof(char *));
    for (int i = 0; i < my_args_length - 1; i++) {
      my_args[i] = argv[arg_offset+i];
    }
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    status = execv(find_executable(my_args[0]), my_args);
    return status;
  }
  else {
	load_config();
	init_intercepts(&graft_config);
    child_processes = vector_init(sizeof(struct graft_process_data));
	graft_monitored_files = vector_init(sizeof(struct graft_file));
    graft_setup_child(child, NULL);
    siginfo_t infop;
    while(vector_size(child_processes) > 0) {
      waitid(P_ALL, 0, &infop, WSTOPPED);
      struct graft_process_data *child;
      int i;
      for (i = 0; i < vector_size(child_processes); i++) {
        child = (struct graft_process_data *) vector_get(child_processes, i);
        if (child->pid == infop.si_pid) {
          break;
        }
      }
      if(WIFEXITED(infop.si_status)) {
				graft_cleanup_child(child, i);
        if (vector_size(child_processes) == 0) {
          return WEXITSTATUS(infop.si_status);
        }
      }
      handle_syscall(child);
      ptrace(PTRACE_SYSCALL,
        child->pid, NULL, NULL);
    }
  }
  return 0;
}
