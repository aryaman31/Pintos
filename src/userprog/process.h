#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <list.h>
#include "threads/synch.h"

typedef int pid_t;                   /* Type for process id.*/

pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);

/* Middleman struct used to allow communication between child and parent threads.*/
struct child_parent_ledger {
  /* Owned by userprog/process.c. */
  struct lock access_lock;           /* Used to lock access between parent and child. */
  struct semaphore blocking_sema;    /* Used to sleep parent when waiting for child.  */
  int child_tid;                     /* Thread id for child.*/

  int exit_code;                     /* Child exit code. */

  bool parent_waited;                /* Stores whether or not parent has called process_wait.*/
  bool child_exited;                 /* Stores whether child exited. */
  bool parent_exited;                /* Stores whether parent exited. */

  struct hash_elem elem;              /* List element.*/
};

/* Struct to store arguments that are passed to start_process. */
struct start_process_args {
  /* Owned by userprog/process.c. */
  char *cmd_line;                      /* Command line input. */
  struct semaphore start_sema;         /* Semaphore to make sure start_process
                                          finishes before process_execute exits. */
  struct semaphore order_sema;         /* Semaphore to make sure ledger is set
                                          up before start_process begins. */
  bool success;                        /* Success status of start_process.*/
};

#endif /* userprog/process.h */
