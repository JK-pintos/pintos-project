#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include <stddef.h>
#include <stdbool.h>
#include "list.h"

#define FD_BLOCK_MAX    128

/* An open file. */
struct file {
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};

struct fdt_block {
    struct file *entry[FD_BLOCK_MAX]; 
    int available_idx;
    struct list_elem   elem;
};

struct inode;

/* Opening and closing files. */
struct file *file_open (struct inode *);
struct file *file_reopen (struct file *);
struct file *file_duplicate (struct file *file);
void file_close (struct file *);
struct inode *file_get_inode (struct file *);

/* Reading and writing. */
off_t file_read (struct file *, void *, off_t);
off_t file_read_at (struct file *, void *, off_t size, off_t start);
off_t file_write (struct file *, const void *, off_t);
off_t file_write_at (struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write (struct file *);
void file_allow_write (struct file *);

/* File position. */
void file_seek (struct file *, off_t);
off_t file_tell (struct file *);
off_t file_length (struct file *);

#endif /* filesys/file.h */
