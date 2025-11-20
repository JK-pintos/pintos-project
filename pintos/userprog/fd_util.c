#include "userprog/fd_util.h"

#include <stdlib.h>
#include <string.h>

#define WORD_SIZE 64

struct fd_table {
    int size;
    int next_fd;
    unsigned long* bitmap;
    struct file** file_list;
};

static int fd_find_next(struct fd_table* fd_t);
static void fd_table_expand(struct fd_table* fd_t);

void fd_init(struct thread* t) {
    t->fd_table = malloc(sizeof(struct fd_table));
    t->fd_table->size = WORD_SIZE;
    t->fd_table->next_fd = 2;
    t->fd_table->bitmap = calloc(1, sizeof(unsigned long));
    t->fd_table->bitmap[0] |= 3;
    t->fd_table->file_list = calloc(t->fd_table->size, sizeof(struct file*));
}

int allocate_fd(struct fd_table* fd_t, struct file* f) {
    if (f == NULL) return -1;
    int cur_fd = fd_t->next_fd;
    fd_t->file_list[cur_fd] = f;
    fd_t->next_fd = fd_find_next(fd_t);
    return cur_fd;
}

struct file* get_file(struct fd_table* fd_t, int fd) {
    if (fd < 0 || fd_t->size <= fd) return NULL;
    return fd_t->file_list[fd];
}

void fd_close(struct fd_table* fd_t, int fd) {
    struct file* file = get_file(fd_t, fd);
    if (file == NULL) return;
    file_close(file);
    fd_t->file_list[fd] = NULL;
    fd_t->bitmap[fd / WORD_SIZE] &= ~(1ULL << (fd % WORD_SIZE));
    if (fd < fd_t->next_fd) fd_t->next_fd = fd;
}

void copy_fd_table(struct fd_table* dst, struct fd_table* src) {
    unsigned long* new_bitmap = calloc(src->size, sizeof(unsigned long));
    struct file** new_file_list = calloc(src->size, sizeof(struct file*));

    memcpy(new_bitmap, src->bitmap, src->size);
    memcpy(new_file_list, src->file_list, src->size);

    free(dst->bitmap);
    free(dst->file_list);
    dst->size = src->size;
    dst->bitmap = new_bitmap;
    dst->file_list = new_file_list;
}

void fd_clean(struct thread* t) {
    for (int i = 2; i < t->fd_table->size; i++) {
        fd_close(t->fd_table, i);
    }
    free(t->fd_table);
    t->fd_table = NULL;
}

static int fd_find_next(struct fd_table* fd_t) {
    int w = fd_t->next_fd / WORD_SIZE;
    while (1) {
        for (; w < fd_t->size / WORD_SIZE; w++) {
            if (fd_t->bitmap[w] != ~0UL) {
                int bit = __builtin_ffsl(~fd_t->bitmap[w]) - 1;
                fd_t->bitmap[w] |= (1ULL << bit);
                return w * WORD_SIZE + bit;
            }
        }
        fd_table_expand(fd_t);
    }
}

static void fd_table_expand(struct fd_table* fd_t) {
    int new_size = fd_t->size * 2;
    unsigned long* new_bitmap = calloc(new_size, sizeof(unsigned long));
    struct file** new_file_list = calloc(new_size, sizeof(struct file*));

    memcpy(new_bitmap, fd_t->bitmap, fd_t->size);
    memcpy(new_file_list, fd_t->file_list, fd_t->size);

    free(fd_t->bitmap);
    free(fd_t->file_list);
    fd_t->size = new_size;
    fd_t->bitmap = new_bitmap;
    fd_t->file_list = new_file_list;
}
