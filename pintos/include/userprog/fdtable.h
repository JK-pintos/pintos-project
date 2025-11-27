#ifndef USERPROG_FDTABLE_H
# define USERPROG_FDTABLE_H

# include "kernel/list.h"
# include "filesys/file.h"
# include "filesys/filesys.h"
# include "threads/malloc.h"
# include "threads/thread.h"

# define FD_BLOCK_MAX   128

/*  stdin, stdout entries
    - 초기화는 init.c 안에서 할당 시스템 세팅이 완료된 이후에
    - 모든 쓰레드의 파일 디스크립터 0, 1 초기 엔트리 값으로 사용됨
    - 사용은 이 헤더파일을 include하는 모든 곳에서          */
extern struct file  *stdin_entry;
extern struct file  *stdout_entry;

/*  file descriptor block
    - 각 쓰레드는 파일디스크립터 블럭(해당 구조체) 단위로 관리
    - 블럭은 고정 크기(FD_BLOCK_MAX)의 entry 배열을 가짐
    - 확장이 필요한 경우 동적할당으로 확장

    - available_idx : 할당 가능한 최소 fd 인덱스
        - syscall_open(), syscall_close()에서 관리
    - elem : list.h 함수 사용을 위해 필요               */
struct                  fdt_block {
    int                 available_idx;
    struct file         *entry[FD_BLOCK_MAX];
    struct list_elem    elem;
};

/*  used in threads/init.c  */
void	            init_std_fds(void);

/*  used in threads/thread.c -> thread_create()  */
bool                fdt_list_init(struct thread* t);

/*  fdt_block interface functions  */
int                 fd_allocate(struct thread* t, struct file* f);
struct fdt_block    *get_fd_block_allocate(struct thread* t, int* fd);
struct fdt_block    *get_fd_block(struct thread *t, int *fd);
struct file*        get_fd_entry(struct thread* t, int fd);
void                fd_close(struct thread *t, int fd);
void                fdt_list_cleanup(struct thread* t);
bool                fdt_block_append(struct thread *t);
void                scan_for_next_fd(struct fdt_block *block);

bool                duplicate_fdt_block(struct fdt_block *parent_block, struct fdt_block *child_block, struct thread *child);
bool                duplicate_fdt_block_list(struct thread *parent, struct thread *child);
bool    dup2_duplicate_fdt_block_list(struct thread *parent, struct thread *child);

#endif

