#ifndef FD_UTIL_H
#define FD_UTIL_H

#include <stdbool.h>

#include "filesys/file.h"
#include "threads/thread.h"

struct fd_table;
void fd_init(struct thread* t);
int allocate_fd(struct fd_table* fd_t, struct file* f);
struct file* get_file(struct fd_table* fd_t, int fd);
void fd_close(struct fd_table* fd_t, int fd);
void fd_close_all(struct fd_table* fd_t);
#endif