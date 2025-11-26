/* Confirm that dup2-linked descriptors stay linked after fork.  The child
   sees the primed offset, advances it once, and the parent observes the
   updated position as soon as the child exits. */

   #include <stdio.h>
   #include <syscall.h>
   #include "tests/lib.h"
   
   int
   main (int argc UNUSED, char *argv[] UNUSED) {
     test_name = "dup2-fork-link";
   
     char buf[16];
     int fd = open ("sample.txt");
     CHECK (fd > 1, "open \"sample.txt\"");
     CHECK (read (fd, buf, 5) == 5, "set offset to 5");
     int dup_fd = dup2 (fd, 30);
     CHECK (dup_fd == 30, "dup2 to 30");
     pid_t pid = fork ("dup-child");
     if (pid < 0)
       fail ("fork failed");
   
     if (pid == 0) {
       int off_fd = tell (fd);
       int off_dup = tell (dup_fd);
       if (off_fd != 5 || off_dup != 5)
         fail ("child inherited offsets fd=%d dup=%d (expected 5)", off_fd, off_dup);
   
       CHECK (read (dup_fd, buf, 7) == 7, "child read dup fd");
       off_fd = tell (fd);
       off_dup = tell (dup_fd);
       if (off_fd != 12 || off_dup != 12)
         fail ("child offsets diverged after read (fd=%d dup=%d)", off_fd, off_dup);
       exit (0);
     }
   
     if (pid > 0)
       CHECK (wait (pid) == 0, "wait child");
     return 0;
   }