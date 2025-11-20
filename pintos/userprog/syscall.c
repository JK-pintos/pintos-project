#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/fdtable.h"
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

static bool	    valid_address(const void *addr);

static void     syscall_halt(void);
static void     syscall_exit(int status);
//static tid_t  syscall_fork(const char *thread_name);
//static int    syscall_exec(const char *cmd_line);
static int      syscall_wait(int pid);
static bool     syscall_create(const char *file, unsigned initial_size);
static bool     syscall_remove(const char *file);
static int      syscall_open(const char *file);
static int      syscall_filesize(int fd);
static int      syscall_read(int fd, void *buffer, unsigned size);
static int      syscall_write(int fd, const void* buffer, unsigned size);
static void     syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void     syscall_close(int fd);

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

static bool	valid_address(const void *addr)
{
	if (addr == NULL || !(is_user_vaddr(addr)) || !pml4_get_page(thread_current()->pml4, addr))
		return false;
    else
	    return true;
}

static void syscall_halt(void) { power_off(); }

static void syscall_exit(int status) {
    thread_current()->my_entry->exit_status = status;
    thread_exit();
}

static int syscall_wait(int pid) { return process_wait(pid); }

static bool     syscall_create(const char *file, unsigned initial_size)
{
    if (valid_address(file) == false)
        syscall_exit(-1);
    return filesys_create(file, initial_size); 
}

static bool     syscall_remove(const char *file)
{
    if (valid_address(file) == false)
        syscall_exit(-1);

    return filesys_remove(file);
}

static int      syscall_open(const char *file)
{
    struct file         *new_entry;

    if (valid_address(file) == false)
        syscall_exit(-1);
    
    new_entry = filesys_open(file);
    if (!new_entry)
        return -1;
    else
        return fd_allocate(thread_current(), new_entry);
}

static int      syscall_filesize(int fd)
{
    struct file *entry;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdin_entry || entry == stdout_entry)
        return -1;
    else
        return file_length(entry);
}

static int stdin_read(void *buffer, unsigned size)
{
    unsigned char   *buff = (char *)buffer;
    int             read_bytes = 0;
    unsigned char   c;

    while (read_bytes < size)
    {
        buff[read_bytes] = input_getc();
        read_bytes++;
    }
    return read_bytes;
}

static int      syscall_read(int fd, void *buffer, unsigned size)
{
    struct file *entry;

    if (size == 0)
        return 0;
    
    if (valid_address(buffer) == false || valid_address(buffer + size - 1) == false)
        syscall_exit(-1);

    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdout_entry)
        return -1;
    else if (entry == stdin_entry)
        return stdin_read(buffer, size);
    else
        return file_read(entry, buffer, size);
}

static int      stdout_write(void *buffer, unsigned size)
{
    putbuf(buffer, size);
    return size;
}

static int      syscall_write(int fd, const void* buffer, unsigned size)
{
    struct file *entry;

    if (valid_address(buffer) == false || valid_address(buffer + size - 1) == false)
        syscall_exit(-1);

    entry = get_fd_entry(thread_current(), fd);
    if (!entry || entry == stdin_entry)
        return -1;
    else if (entry == stdout_entry)
        return stdout_write(buffer, size);
    else
        return file_write(entry, buffer, size);
}

static void     syscall_seek(int fd, unsigned position)
{
    struct file *entry;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry)
        return ;
    
    file_seek(entry, position);
}

static unsigned syscall_tell(int fd)
{
    struct file *entry;

    entry = get_fd_entry(thread_current(), fd);
    if (!entry)
        return -1;
    else
        return file_tell(entry);
}

static void     syscall_close(int fd)
{
    fd_close(thread_current(), fd);
}
