#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
/* Owned by syscall.c. */
void syscall_init (void);
void deny_write_executable(const char *file_name);
bool check_file_exists(char *file_name);
void safe_exit (int status);
struct lock *get_file_lock(void);
#endif /* userprog/syscall.h */
