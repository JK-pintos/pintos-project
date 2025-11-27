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

bool fdt_list_init(struct thread* t) {
    struct fdt_block* first_fdt_block;

    list_init(&(t->fdt_block_list));
    first_fdt_block = (struct fdt_block*)calloc(1, sizeof(struct fdt_block));
    if (!first_fdt_block) return false;

    first_fdt_block->entry[0] = stdin_entry;
    first_fdt_block->entry[1] = stdout_entry;
    first_fdt_block->available_idx = 2;
    list_push_back(&(t->fdt_block_list), &(first_fdt_block->elem));
    return true;
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

    if (false == fdt_block_append(t))
    {
        file_close(f);
        return -1;
    }
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

    if (e == tail || block_start_fd + FD_BLOCK_MAX <= *fd) return NULL;

    block = list_entry(e, struct fdt_block, elem);
    *fd -= block_start_fd;  // 블록 안의 fd로 재조정
    return block;
}

struct fdt_block* get_fd_block_allocate(struct thread* t, int* fd) {
    struct list_elem* e;
    struct list_elem* tail;
    struct fdt_block* block;
    int block_start_fd = 0;

    if (*fd < 0) return NULL;

    e = list_begin(&(t->fdt_block_list));
    tail = list_tail(&(t->fdt_block_list));
    while ((e != tail) && block_start_fd + FD_BLOCK_MAX <= *fd) {
        e = list_next(e);
        if (e != tail)
            block_start_fd += FD_BLOCK_MAX;
    }

    while (block_start_fd + FD_BLOCK_MAX <= *fd)
    {
        if (false == fdt_block_append(t))
            return NULL;
        e = list_prev(tail);
        block_start_fd += FD_BLOCK_MAX;
    }
    
    // if (e == tail)
    //     e = list_prev(tail);

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

    block = get_fd_block(t, &fd);
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
            if (entry && entry != stdin_entry && entry != stdout_entry) file_close(entry);
            block->entry[i] = NULL;
        }
        free (block);
    }
}

bool fdt_block_append(struct thread* t) {
    struct fdt_block* block;

    block = (struct fdt_block*)calloc(1, sizeof(struct fdt_block));
    if (!block) return false;
    list_push_back(&(t->fdt_block_list), &(block->elem));
    return true;
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

bool    duplicate_fdt_block(struct fdt_block *parent_block, struct fdt_block *child_block, struct thread *child)
{
    struct file     *parent_entry;
    struct file     *new_entry;
    int             i = 0;

    if (!child_block)
    {
        child_block = (struct fdt_block *)calloc(1, sizeof(struct fdt_block));
        if (!child_block)
            return false;
        list_push_back(&(child->fdt_block_list), &(child_block->elem));
    }

    while (i < FD_BLOCK_MAX)
    {
        if (parent_block->entry[i] == stdin_entry || \
            parent_block->entry[i] == stdout_entry)
            child_block->entry[i] = parent_block->entry[i];
        else if (parent_block->entry[i])
        {
            new_entry = file_duplicate(parent_block->entry[i]);
            if (!new_entry)
                return false;
            child_block->entry[i] = new_entry;
        }
        i++;
    }
    child_block->available_idx = parent_block->available_idx;
    return true;
}

bool    duplicate_fdt_block_list(struct thread *parent, struct thread *child)
{
    struct list_elem    *parent_e;
    struct list_elem    *child_e;
    struct list_elem    *parent_tail;
    struct list_elem    *child_tail;
    struct fdt_block    *parent_block;
    struct fdt_block    *child_block = NULL;

    parent_e = list_begin(&(parent->fdt_block_list));
    parent_tail = list_tail(&(parent->fdt_block_list));
    child_e = list_begin(&(child->fdt_block_list));
    child_tail = list_tail(&(child->fdt_block_list));

    while (parent_e != parent_tail)
    {
        parent_block = list_entry(parent_e, struct fdt_block, elem);
        if (child_e != child_tail)
            child_block = list_entry(child_e, struct fdt_block, elem);
        else
            child_block = NULL;

        if (false == duplicate_fdt_block(parent_block, child_block, child))
        {
            fdt_list_cleanup(child);
            return false;
        }

        if (child_e != child_tail)
            child_e = list_next(child_e);
        else
            child_block = NULL;
        parent_e = list_next(parent_e);
    }
    return true;
}

bool    clone_fdt_list_structure(struct thread *parent, struct thread *child)
{
    struct list_elem    *child_e;
    struct list_elem    *child_tail;
    struct fdt_block    *child_block;

    child_e = list_begin(&(child->fdt_block_list));
    child_tail = list_tail(&(child->fdt_block_list));
    while (child_e != child_tail)
    {
        child_block = list_entry(child_e, struct fdt_block, elem);
        memset(child_block->entry, 0, sizeof(child_block->entry));
        child_e = list_next(child_e);
    }

    while (list_size(&(parent->fdt_block_list)) != list_size(&(child->fdt_block_list)))
    {
        if (false == fdt_block_append(child))
            return false;
    }
    return true;
}

bool    duplicate_all_file(int i, struct list_elem *parent_e, \
    struct list_elem *parent_tail, struct list_elem *child_e, \
    struct list_elem *child_tail)
{
    int ref;
    int j = 0;
    struct fdt_block    *parent_block;
    struct fdt_block    *child_block;
    struct file         *entry_to_dup;
    struct file         *new_entry;

    parent_block = list_entry(parent_e, struct fdt_block, elem);
    child_block = list_entry(child_e, struct fdt_block, elem);
    
    entry_to_dup = parent_block->entry[i];
    ref = get_ref_count(entry_to_dup);
    new_entry = file_duplicate(entry_to_dup);
    if (!new_entry)
        return false;

    while (ref > 0 && parent_e != parent_tail && child_e != child_tail)
    {
        while (ref > 0 && i < FD_BLOCK_MAX)
        {
            if (parent_block->entry[i] == entry_to_dup)
            {
                child_block->entry[i] = new_entry;
                ref --;
            }
            i++;
        }
        parent_e = list_next(parent_e);
        child_e = list_next(child_e);
        parent_block = list_entry(parent_e, struct fdt_block, elem);
        child_block = list_entry(child_e, struct fdt_block, elem);
        i = 0;
    }
    return true;
}

bool    dup2_duplicate_fdt_block_list(struct thread *parent, struct thread *child)
{
    // child -> parent list size만큼 블록 만들어서 공간 확보 -> memset으로 다 null 초기화
    
    // 하나씩 복사 
    // 만약 child_block->entry[i]가 null이 아니라면
        // pass
    // null이면 부모 entry보기
        // 부모 entry가 stdin, stdout이면 그냥복사
        // 아니면 일단 duplicate -> 그 다음에 필요한 곳에 다 넣기 
    // available idx도 복사

    struct list_elem    *parent_e;
    struct list_elem    *parent_tail;
    struct fdt_block    *parent_block;
    struct list_elem    *child_e;
    struct list_elem    *child_tail;
    struct fdt_block    *child_block;
    int                 i;

    if (false == clone_fdt_list_structure(parent, child))
        return false;
    
    parent_e = list_begin(&(parent->fdt_block_list));
    parent_tail = list_tail(&(parent->fdt_block_list));
    child_e = list_begin(&(child->fdt_block_list));
    child_tail = list_tail(&(child->fdt_block_list));
    
    while (parent_e != parent_tail)
    {
        parent_block = list_entry(parent_e, struct fdt_block, elem);
        child_block = list_entry(child_e, struct fdt_block, elem);
        
        child_block->available_idx = parent_block->available_idx;
        
        for (i = 0; i < FD_BLOCK_MAX; i++)
        {
            if (child_block->entry[i])
                continue ;
            if (!(parent_block->entry[i]) || parent_block->entry[i] == stdin_entry || parent_block->entry[i] == stdout_entry)
                child_block->entry[i] = parent_block->entry[i];
            else if (false == duplicate_all_file(i, parent_e, parent_tail, child_e, child_tail))
                return false;
        }

        parent_e = list_next(parent_e);
        child_e = list_next(child_e);
    }
    return true;
}