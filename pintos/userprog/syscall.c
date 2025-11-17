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

static void halt(void);
static void exit(int status);
static int wait(int pid);
static bool create(const char* file, unsigned initial_size);
static bool remove(const char* file);
static int write(int fd, const void* buffer, unsigned size);

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
void syscall_handler(struct intr_frame* f UNUSED) {
    uint64_t args1 = f->R.rdi, args2 = f->R.rsi, args3 = f->R.rdx;
    switch (f->R.rax) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(args1);
            break;
        case SYS_FORK:
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            f->R.rax = wait(args1);
            break;
        case SYS_CREATE:
            f->R.rax = create(args1, args2);
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            break;
        case SYS_WRITE:
            f->R.rax = write(args1, args2, args3);
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
    }
}

static void halt(void) { power_off(); }

static void exit(int status) {
    thread_current()->child_entry->exit_status = status;
    thread_exit();
}

static int wait(int pid) { return process_wait(pid); }

static bool create(const char* file, unsigned initial_size) {
    if (file == NULL || !validate_ptr(file, false)) exit(-1);
    lock_acquire(&file_lock);
    bool result = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return result;
}

static bool remove(const char* file) {
    if (file == NULL || !validate_ptr(file, false)) exit(-1);
    lock_acquire(&file_lock);
    bool result = filesys_remove(file);
    lock_release(&file_lock);
    return true;
}

static int write(int fd, const void* buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
}
