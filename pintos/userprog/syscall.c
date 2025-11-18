#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "threads/init.h"   

#include "userprog/process.h"   
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

static struct lock file_lock;

static void syscall_halt(void);
static void syscall_exit(int status);
static int syscall_wait(int pid);
static int syscall_write(int fd, const void* buffer, unsigned size);
static bool syscall_create(const char *flie, unsigned initial_size);
static int syscall_open(const char *file);
static void syscall_close(int fd);

static void fd_close(struct thread *t, int fd);
static int fd_allocate(struct thread *t, struct file *f);
static void grow_fd_table(struct thread *t);
static struct file* find_file_by_fd(int fd);
static void check_address(const void *addr);

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&file_lock);
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
            break;
    }
}

static void syscall_halt(void) { power_off(); }

static void syscall_exit(int status) {
    thread_current()->my_entry->exit_status = status;
    thread_exit();
}

static int syscall_wait(int pid) { return process_wait(pid); }

static int syscall_write(int fd, const void* buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
}

static bool syscall_create(const char *file, unsigned initial_size){
	check_address(file);
	lock_acquire(&file_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return success;

}

static void check_address(const void *addr){
	if (addr == NULL || !is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
	syscall_exit(-1);
}

static int syscall_open(const char *file){
	check_address(file);

	struct file *f = filesys_open(file);
	if (f == NULL) return -1;

	struct thread *cur = thread_current();
	int fd = fd_allocate(cur ,f);
	if (fd == -1){
		file_close(f);
		return -1;
	}
	return fd;
}

static void syscall_close(int fd){
	fd_close(thread_current(), fd);
}


static void fd_close(struct thread *t, int fd){
	if (fd < 3 || fd >= t->fd_table_size) return;
	if (t->fd_table[fd] == NULL) return;
	file_close(t->fd_table[fd]);
	t->fd_table[fd] = NULL;
}

static int fd_allocate(struct thread *t, struct file *f){
    while (t->next_fd >= t->fd_table_size) {
        grow_fd_table(t); 
    }
    t->fd_table[t->next_fd] = f;

    return t->next_fd++;
}

static void grow_fd_table(struct thread *t) {
    int new_size = t->fd_table_size * 2;
    struct file **new_table = malloc(sizeof(struct file*) * new_size);

    for (int i = 0; i < new_size; i++) {
        new_table[i] = (i < t->fd_table_size) ? t->fd_table[i] : NULL;
    }
    free(t->fd_table);
    t->fd_table = new_table;
    t->fd_table_size = new_size;
}

static struct file* find_file_by_fd(int fd) {
    struct thread *t = thread_current();

    if (fd < 0 || fd >= t->fd_table_size)
        return NULL;

    return t->fd_table[fd];
}