#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/fdtable.h"
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
// static tid_t  syscall_fork(const char *thread_name);
// static int    syscall_exec(const char *cmd_line);
static int syscall_wait(int pid);
static bool syscall_create(const char* file, unsigned initial_size);
static bool syscall_remove(const char* file);
static int syscall_open(const char* file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void* buffer, unsigned size);
static int syscall_write(int fd, const void* buffer, unsigned size);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
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
            f->R.rax = syscall_exec(arg1);
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
            syscall_seek(arg1, arg2);
            break;
        case SYS_TELL:
            f->R.rax = syscall_tell(arg1);
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

static pid_t syscall_fork(const char* thread_name, struct intr_frame* if_) {
    if (thread_name == NULL || !validate_ptr(thread_name, false)) syscall_exit(-1);
    return process_fork(thread_name, if_);
}

static int syscall_exec(const char* cmd_line) {
    if (cmd_line == NULL || !validate_ptr(cmd_line, false)) syscall_exit(-1);
    process_exec(cmd_line);
    syscall_exit(-1);
}

static int syscall_wait(int pid) { return process_wait(pid); }

static bool syscall_create(const char* file, unsigned initial_size) {
    bool success;

    if (!valid_address(file, false)) syscall_exit(-1);
    lock_acquire(&file_lock);
    success = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return success;
}

static bool syscall_remove(const char* file) {
    bool success;

    if (!valid_address(file, false)) syscall_exit(-1);
    lock_acquire(&file_lock);
    success = filesys_remove(file);
    lock_release(&file_lock);
    return success;
}

static int syscall_open(const char* file) {
    struct file* new_entry;
    if (!valid_address(file, false)) syscall_exit(-1);
    lock_acquire(&file_lock);
    new_entry = filesys_open(file);
    lock_release(&file_lock);
    if (!new_entry) return -1;
    return fd_allocate(thread_current(), new_entry);
}

static int syscall_filesize(int fd) {
    struct file* entry;
    int result;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdin_entry || entry == stdout_entry) return -1;

    lock_acquire(&file_lock);
    result = file_length(entry);
    lock_release(&file_lock);
    return result;
}

static int syscall_read(int fd, void* buffer, unsigned size) {
    struct file* entry;
    int result;
    if (size == 0) return 0;

    if (!valid_address(buffer, true) || !valid_address(buffer + size - 1, true)) syscall_exit(-1);
    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdout_entry) return -1;

    lock_acquire(&file_lock);
    if (entry == stdin_entry) {
        for (int i = 0; i < size; i++) ((char*)buffer)[i] = input_getc();
        result = size;
    } else {
        result = file_read(entry, buffer, size);
    }
    lock_release(&file_lock);
    return result;
}

static int syscall_write(int fd, const void* buffer, unsigned size) {
    struct file* entry;
    int result;

    if (!valid_address(buffer, false) || !valid_address(buffer + size - 1, false)) syscall_exit(-1);
    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdin_entry) return -1;

    lock_acquire(&file_lock);
    if (entry == stdout_entry) {
        putbuf(buffer, size);
        result = size;
    } else {
        result = file_write(entry, buffer, size);
    }
    lock_release(&file_lock);
    return result;
}

static void syscall_seek(int fd, unsigned position) {
    struct file* entry;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry) return;
    lock_acquire(&file_lock);
    file_seek(entry, position);
    lock_release(&file_lock);
}

static unsigned syscall_tell(int fd) {
    struct file* entry;
    unsigned result;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry) return 0;

    lock_acquire(&file_lock);
    result = file_tell(entry);
    lock_release(&file_lock);
    return result;
}

static void syscall_close(int fd) {
    lock_acquire(&file_lock);
    fd_close(thread_current(), fd);
    lock_release(&file_lock);
}
