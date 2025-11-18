#include "userprog/fd_util.h"

#include <stdlib.h>
#include <string.h>

#include "threads/thread.h"

#define FD_TABLE_DAFULT_SIZE 16;

static void fd_table_expand();

void fd_init() {
    struct thread* cur = thread_current();
    cur->fd_table_size = FD_TABLE_DAFULT_SIZE;
    cur->fd_table = calloc(1, sizeof(struct file*) * cur->fd_table_size);
    cur->fd_table[1] = malloc(sizeof(struct file*));
}

int allocate_fd(struct file* f) {
    if (f == NULL) return -1;
    struct thread* cur = thread_current();
    int index = 2;
    while (1) {
        for (; index < cur->fd_table_size; index++) {
            if (cur->fd_table[index] == NULL) {
                cur->fd_table[index] = f;
                return index;
            }
        }
        fd_table_expand();
    }
}

static void fd_table_expand() {
    struct thread* cur = thread_current();
    int expand_size = cur->fd_table_size * 2;
    struct file** new_table = calloc(1, sizeof(struct file*) * expand_size);
    memcpy(new_table, cur->fd_table, sizeof(struct file*) * cur->fd_table_size);

    free(cur->fd_table);
    cur->fd_table = new_table;
    cur->fd_table_size = expand_size;
}