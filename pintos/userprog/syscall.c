#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/fd_util.h"
#include "userprog/gdt.h"
#include "userprog/validate.h"

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

struct lock file_lock;

static void syscall_halt(void);
static void syscall_exit(int status);
static int syscall_wait(int pid);
static bool syscall_create(const char* file, unsigned initial_size);
static bool syscall_remove(const char* file);
static int syscall_open(const char* file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void* buffer, unsigned size);
static int syscall_write(int fd, const void* buffer, unsigned size);
static void syscall_close(int fd);

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
            f->R.rax = syscall_remove(arg1);
            break;
        case SYS_OPEN:
            f->R.rax = syscall_open(arg1);
            break;
        case SYS_FILESIZE:
            f->R.rax = syscall_filesize(arg1);
            break;
        case SYS_READ:
            f->R.rax = syscall_read(arg1, arg2, arg3);
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

static void syscall_halt(void) { power_off(); }

static void syscall_exit(int status) {
    thread_current()->my_entry->exit_status = status;
    thread_exit();
}

static int syscall_wait(int pid) { return process_wait(pid); }

static bool syscall_create(const char* file, unsigned initial_size) {
    if (file == NULL || !validate_ptr(file, false)) syscall_exit(-1);
    lock_acquire(&file_lock);
    bool result = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return result;
}

static bool syscall_remove(const char* file) {
    if (file == NULL || !validate_ptr(file, false)) syscall_exit(-1);
    lock_acquire(&file_lock);
    bool result = filesys_remove(file);
    lock_release(&file_lock);
    return result;
}

static int syscall_open(const char* file) {
    if (file == NULL || !validate_ptr(file, false)) syscall_exit(-1);
    struct thread* cur = thread_current();
    lock_acquire(&file_lock);
    struct file* open_file = filesys_open(file);
    int result = allocate_fd(open_file);
    lock_release(&file_lock);
    return result;
}

static int syscall_filesize(int fd) {
    struct thread* cur = thread_current();
    if (fd < 0 || cur->fd_table_size <= fd || cur->fd_table[fd]) return;
    lock_acquire(&file_lock);
    int result = file_length(cur->fd_table[fd]);
    lock_release(&file_lock);
    return result;
}

int syscall_read(int fd, void* buffer, unsigned size) {

}

static int syscall_write(int fd, const void* buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
}

static void syscall_close(int fd) {
    struct thread* cur = thread_current();
    if (fd < 0 || cur->fd_table_size <= fd || cur->fd_table[fd]) return;
    lock_acquire(&file_lock);
    file_close(fd);
    cur->fd_table[fd] = NULL;
    lock_release(&file_lock);
}
