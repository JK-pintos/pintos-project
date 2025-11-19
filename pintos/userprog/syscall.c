#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame*);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static bool	valid_address(const void *addr);

static void syscall_halt(void);
static void syscall_exit(int status);
static int syscall_wait(int pid);
static int syscall_write(int fd, const void* buffer, unsigned size);
static bool syscall_create(const char *file, unsigned initial_size);
static int	syscall_open(const char *file);
static void	syscall_close(int fd);

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame* f) {
    uint64_t arg1 = f->R.rdi, arg2 = f->R.rsi, arg3 = f->R.rdx;
    switch (f->R.rax) {
        case SYS_HALT:
            syscall_halt();
            break;
        case SYS_EXIT:
            syscall_exit(arg1);
            break;
        case SYS_FORK:
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            f->R.rax = syscall_wait(arg1);
            break;
        case SYS_CREATE:
			f->R.rax = syscall_create(arg1, arg2);
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
			f->R.rax = syscall_open(arg1);
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            break;
        case SYS_WRITE:
            f->R.rax = syscall_write(arg1, arg2, arg3);
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            syscall_close(arg1);
            break;
    }
}

static bool	valid_address(const void *addr)
{
	// is_user_vaddr를 먼저 해줘야 함 -> 아니면 pml4에서 assert -> program shutdown 
	if (addr == NULL || !(is_user_vaddr(addr)) || !pml4_get_page(thread_current()->pml4, addr))
		return false;
	return true;
}

static void syscall_halt(void) { power_off(); }

static void syscall_exit(int status) {
    thread_current()->my_entry->exit_status = status;
    thread_exit();
}

static int syscall_wait(int pid) { return process_wait(pid); }

static int syscall_write(int fd, const void* buffer, unsigned size) {
    // if (fd == 1) {
    //     putbuf(buffer, size);
    //     return size;
    // }
  

    // size 유효성 검사도 해야함 
    if (valid_address(buffer) == false)
        syscall_exit(-1);
    #ifdef USERPROG
    struct list_elem *e = list_begin(&(thread_current()->fdt_block_list));
    int block_start_fd = 0;
    while (block_start_fd + FD_BLOCK_MAX <= fd)
    {
        e = list_next(e);
        if (e == list_tail(&(thread_current()->fdt_block_list)))
            return -1; //할당안된 Fd를 넘겼다고 판단
        block_start_fd += FD_BLOCK_MAX;
    }
    if (block_start_fd + FD_BLOCK_MAX <= fd)
        return -1;
    struct fdt_block    *block = list_entry(e, struct fdt_block, elem);
    if (block->entry[fd - block_start_fd] == NULL || block->entry[fd - block_start_fd] == fake_stdin_entry)
        return (-1);
    if (block->entry[fd - block_start_fd] == fake_stdout_entry)
    {
        putbuf(buffer,size);
        return size;
    }
    
     
    #endif
}

static bool syscall_create(const char *file, unsigned initial_size)
{
	if (valid_address(file) == false)
		syscall_exit(-1); // return이 아니라? 
	return filesys_create(file, initial_size); 
	// size가 0이어도 정상
		// 파일은 존재하지만 데이터가 없는 경우 
}

static void update_block_available_idx(struct fdt_block *block)
{
    // 한 블럭의 available idx 갱신 -> 다른 블록 보지 X 
    // 이전의 available idx에는 entry가 들어간 상황 -> 그 뒤 상황
        // available idx보다 큰 가능한 idx를 찾아줌
        // 왜 그 전의 idx는 탐색 x? -> close에서 갱신해줄 거라고 생각하고 
    int i = 1; 

    while (block->available_idx + i < FD_BLOCK_MAX)
    {
        if (block->entry[block->available_idx + i] == NULL)
        {
            block->available_idx += i;
            return ;
        }
        i++;
    }
    block->available_idx = -1;
}

static int	syscall_open(const char *file)
{
	struct file *new_entry;
    struct list_elem *e;
    struct fdt_block *block;
    int block_base_idx = 0;
    int fd = 0;

	if (valid_address(file) == false)
		syscall_exit(-1);
	
    new_entry = filesys_open(file);
    if (!new_entry)
        return -1;
    
    lock_acquire(&(thread_current()->fdt_lock));
    if (list_empty(&(thread_current()->fdt_block_list)) == false)
    {
        e = list_begin(&(thread_current()->fdt_block_list));
        while(e != list_tail(&(thread_current()->fdt_block_list)))
        {
            block = list_entry(e, struct fdt_block, elem);
            if (0 <= block->available_idx && block->available_idx < FD_BLOCK_MAX)
            {// 위처럼 그냥 막을지 아니면 추가하고 available_idx를 체크해서 유효하지 않은 인덱스면 -1로 바꾸는 작업을 할지
                fd = block_base_idx + block->available_idx;
                block->entry[block->available_idx] = new_entry;
                update_block_available_idx(block);
                lock_release(&(thread_current()->fdt_lock));
                return (fd);
            }
            e = list_next(e);
            block_base_idx += FD_BLOCK_MAX;
        }
        // while문을 종료되었다는 것은 맞는 블록을 찾지 못했다는 것 -> 할당하고 뒤에 붙여줘야 함 -> 아래로 내려감 
    }

    block = (struct fdt_block *)malloc(sizeof (struct fdt_block));
    if (!block)
        PANIC("malloc failed\n");
    memset(block, 0, sizeof(struct fdt_block));
    block->entry[0] = new_entry;
    block->available_idx = 1;
    list_push_back(&(thread_current()->fdt_block_list), &(block->elem));
    fd = block_base_idx;
    lock_release(&(thread_current()->fdt_lock));
    return fd;
}

static void	syscall_close(int fd)
{
    struct file *close_entry;
    struct list_elem *e;
    struct fdt_block *block;
    int block_base_idx = 0;
    
    lock_acquire(&(thread_current()->fdt_lock));
    if (fd < 0 || list_empty(&(thread_current()->fdt_block_list)))
    {
        lock_release(&(thread_current()->fdt_lock));
        return ;
    }
    
    e = list_begin(&(thread_current()->fdt_block_list));
    while (e != list_tail(&(thread_current()->fdt_block_list)))
    {
        if (block_base_idx <= fd && fd < block_base_idx + FD_BLOCK_MAX)
        {
            block = list_entry(e, struct fdt_block, elem);
            close_entry = block->entry[fd - block_base_idx];
            block->entry[fd - block_base_idx] = NULL;
            if (close_entry != NULL && close_entry != fake_stdin_entry && close_entry != fake_stdout_entry)
            {
                file_close (close_entry); 
            }
            if (fd - block_base_idx < block->available_idx)
                block->available_idx = fd - block_base_idx;
            lock_release(&(thread_current()->fdt_lock));
            return ;
        }
        e = list_next(e);
        block_base_idx += FD_BLOCK_MAX;
    }
    lock_release(&(thread_current()->fdt_lock));
}