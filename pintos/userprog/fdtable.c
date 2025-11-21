#include "userprog/fdtable.h"

struct file* stdin_entry = NULL;
struct file* stdout_entry = NULL;

/* init stdin, stdout entry (fake) */
void init_std_fds() {
    stdin_entry = (struct file*)malloc(sizeof(struct file*));
    if (!stdin_entry) PANIC("malloc failed\n");
    stdout_entry = (struct file*)malloc(sizeof(struct file*));
    if (!stdout_entry) PANIC("malloc failed\n");
}

void fdt_list_init(struct thread* t) {
    struct fdt_block* first_fdt_block;

    list_init(&(t->fdt_block_list));
    first_fdt_block = (struct fdt_block*)calloc(1, sizeof(struct fdt_block));
    if (!first_fdt_block) PANIC("malloc failed\n");

    first_fdt_block->entry[0] = stdin_entry;
    first_fdt_block->entry[1] = stdout_entry;
    first_fdt_block->available_idx = 2;
    list_push_back(&(t->fdt_block_list), &(first_fdt_block->elem));
}

int fd_allocate(struct thread* t, struct file* f) {
    struct list_elem* e;
    struct list_elem* tail;
    struct fdt_block* block;
    int block_base_idx = 0;
    int fd = 0;

    if (!list_empty(&(t->fdt_block_list))) {
        e = list_begin(&(t->fdt_block_list));
        tail = list_tail(&(t->fdt_block_list));
        while (e != tail) {
            block = list_entry(e, struct fdt_block, elem);
            if (0 <= block->available_idx && block->available_idx < FD_BLOCK_MAX) {
                block->entry[block->available_idx] = f;
                fd = block_base_idx + block->available_idx;
                scan_for_next_fd(block);
                return fd;
            }
            e = list_next(e);
            block_base_idx += FD_BLOCK_MAX;
        }
    }

    fdt_block_append(t);
    block = list_entry(list_prev(tail), struct fdt_block, elem);
    block->entry[0] = f;
    block->available_idx = 1;
    fd = block_base_idx;
    return fd;
}

struct fdt_block* get_fd_block(struct thread* t, int* fd) {
    struct list_elem* e;
    struct list_elem* tail;
    struct fdt_block* block;
    int block_start_fd = 0;

    if (*fd < 0) return NULL;

    e = list_begin(&(t->fdt_block_list));
    tail = list_tail(&(t->fdt_block_list));
    while (block_start_fd + FD_BLOCK_MAX <= *fd) {
        if (e == tail) break;
        e = list_next(e);
        block_start_fd += FD_BLOCK_MAX;
    }

    if (block_start_fd + FD_BLOCK_MAX <= *fd) return NULL;

    block = list_entry(e, struct fdt_block, elem);
    *fd = *fd - block_start_fd;  // 블록 안의 fd로 재조정
    return block;
}

struct file* get_fd_entry(struct thread* t, int fd) {
    struct fdt_block* block;

    if (fd < 0) return NULL;
    block = get_fd_block(t, &fd);  // 해당 함수에서 fd값이 블록의 상대 fd로 변함
    if (!block)
        return (NULL);
    else
        return (block->entry[fd]);
}

void fd_close(struct thread* t, int fd) {
    struct fdt_block* block;
    struct file* close_entry;

    block = get_fd_block(thread_current(), &fd);
    if (!block) return;

    close_entry = block->entry[fd];
    block->entry[fd] = NULL;
    if (fd < block->available_idx || block->available_idx == -1) block->available_idx = fd;
    if (close_entry && close_entry != stdin_entry && close_entry != stdout_entry)
        file_close(close_entry);
}

void fdt_list_cleanup(struct thread* t) {
    struct list_elem* e;
    struct fdt_block* block;
    struct file* entry;
    int i;

    while (!list_empty(&(t->fdt_block_list))) {
        e = list_pop_front(&(t->fdt_block_list));
        block = list_entry(e, struct fdt_block, elem);
        for (i = 0; i < FD_BLOCK_MAX; i++) {
            entry = block->entry[i];
            if (entry) file_close(entry);
        }
        free(block);
    }
}

void fdt_block_append(struct thread* t) {
    struct fdt_block* block;

    block = (struct fdt_block*)calloc(1, sizeof(struct fdt_block));
    if (!block) PANIC("malloc failed\n");
    list_push_back(&(t->fdt_block_list), &(block->elem));
}

void scan_for_next_fd(struct fdt_block* block) {
    /*  주어진 fdt_block의 available_idx만 갱신
        기존 availble_idx에 할당이 된 상황에서 함수 호출
        즉, available_idx 이후에 가능한 인덱스를 확인하는 과정
        available_idx 이전에 가능한 인덱스는 없다고 가정
        -> why? close()에서 사용가능한 최소 인덱스를 세팅해줌   */

    int idx = block->available_idx + 1;

    while (idx < FD_BLOCK_MAX) {
        if (block->entry[idx] == NULL) {
            block->available_idx = idx;
            return;
        }
        idx++;
    }
    block->available_idx = -1;
}