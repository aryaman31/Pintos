#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/syscall-nr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/* Lock to synchronize file system access. */
static struct lock file_lock;

static void syscall_handler (struct intr_frame *);
void validate_uaddr(const uint8_t *uaddr, int num_bytes);
void check_file_name(const char *file_name);

struct file *get_file(int fd);
void store_file(int fd, struct file *file);
void remove_file(int fd);

int get_fd(void);

void getArgs (void *sp, int *args, int arg_length);

void halt (struct intr_frame *f, void *sp, int args[3]);
void exit(struct intr_frame *f, void *sp, int args[3]);
void exec (struct intr_frame *f, void *sp, int args[3]);
void wait (struct intr_frame *f, void *sp, int args[3]);
void create (struct intr_frame *f, void *sp, int args[3]);
void remove (struct intr_frame *f, void *sp, int args[3]);
void open (struct intr_frame *f, void *sp, int args[3]);
void filesize (struct intr_frame *f, void *sp, int args[3]);
void read (struct intr_frame *f, void *sp, int args[3]);
void write (struct intr_frame *f, void *sp, int args[3]);
void seek (struct intr_frame *f, void *sp, int args[3]);
void tell (struct intr_frame *f, void *sp, int args[3]);
void close (struct intr_frame *f, void *sp, int args[3]);

// Array to hold function pointers to all indexes. Syscall enums map by index.
static void (*sys_calls[13])(struct intr_frame *f, void *sp, int args[3]) =
 {halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close};

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

// Returns file lock so that it can be used in process.c.
struct lock *get_file_lock(void)
{
  return &file_lock;
}

/* Get the file descriptor from current thread.*/
int get_fd(void) {
  thread_current()->curr_fd ++;
  return thread_current()->curr_fd + 1;
}

/* Get the file from a given file descriptor.*/
struct file *get_file(int fd) {
  lock_acquire(&file_lock);
  struct file_pair dummy_file;
  dummy_file.fd = fd;
  struct hash_elem *file_hash_elem = hash_find(&thread_current()->file_map, &dummy_file.elem);

  if(file_hash_elem == NULL) {
    lock_release(&file_lock);
    safe_exit(-1);
  }

  struct file *output = hash_entry(file_hash_elem, struct file_pair, elem)->file;
  lock_release(&file_lock);
  return output;
}

/* Store file in filesystem.*/
void store_file(int fd, struct file *file) {
  lock_acquire(&file_lock);
  struct file_pair *new_entry = malloc(sizeof(struct file_pair));

  if(new_entry == NULL) {
    lock_release(&file_lock);
    safe_exit(-1);
  }

  new_entry->fd = fd;
  new_entry->file = file;
  bool success = hash_insert(&thread_current()->file_map, &new_entry->elem) == NULL;
  lock_release(&file_lock);

  if(!success)
    safe_exit(-1);
}

/* Remove file from filesystem.*/
void remove_file(int fd) {
  lock_acquire(&file_lock);
  struct file_pair dummy_file;
  dummy_file.fd = fd;
  bool success = hash_delete(&thread_current()->file_map, &dummy_file.elem) != NULL;
  lock_release(&file_lock);

  if(!success)
    safe_exit(-1);
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user (const uint8_t *uaddr)
{
     int result;
     asm ("movl $1f, %0; movzbl %1, %0; 1:"
          : "=&a" (result) : "m" (*uaddr));
     return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte)); return error_code != -1;
}

/* Validate virtual memory address, else safe_exit.*/
void validate_uaddr(const uint8_t *uaddr, int num_bytes)
{
  int curr_off = 0;
  while (curr_off < num_bytes) {
    if(!is_user_vaddr(uaddr + curr_off) || get_user(uaddr + curr_off) == -1)
      safe_exit(-1);
    curr_off += PGSIZE;
  }
  if(!is_user_vaddr(uaddr + num_bytes - 1) || get_user(uaddr + num_bytes - 1) == -1)
    safe_exit(-1);
}

/* Ensure file name is not NULL, else safe_exit*/
void check_file_name(const char *file_name) {
  if(file_name == NULL)
    safe_exit(-1);
}

/* Check whether a given file exists in the file system.*/
bool check_file_exists(char *file_name)
{
  bool success = true;

  if(file_name == NULL)
    return false;

  lock_acquire(&file_lock);
  struct file *new_file = filesys_open(file_name);

  if(new_file == NULL)
    success = false;

  file_close(new_file);
  lock_release(&file_lock);
  return success;
}

/* Get arguments for system call.*/
void getArgs (void *sp, int *args, int arg_length)
{
  for(int i = 0; i < arg_length; i++)
  {
    void *addr = sp + ((i + 1) * 4);
    validate_uaddr((const uint8_t *)addr, 4);
    args[i] = *((int *)addr);
  }
}

/* Handles syscalls. Validates the stack pointer and gets the system call number
 from this address. Creates a 3 element array to store arguments and then calls
 the appropriate syscall from the sys_calls array which stores function pointers
  to each of the calls. */

static void syscall_handler (struct intr_frame *f)
{
  void *sp = f->esp;
  validate_uaddr((const uint8_t *)sp, 4);
  int system_call_num = *((int *)sp);
  int args[3];
  sys_calls[system_call_num](f, sp, args);
}

/* Terminate Pintos by calling shutdown_power_off().*/
void halt (struct intr_frame *f UNUSED, void *sp UNUSED, int args[3] UNUSED)
{
  shutdown_power_off();
}

/* Terminate current user program and send its exit status to kernel.*/
void exit(struct intr_frame *f UNUSED, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  int status = (int) args[0];
  safe_exit(status);
}

/* Exit point for all programs
 * Close all open files and prints exit code to stdout.
 * Exits thread. */
void safe_exit (int status)
{
  lock_acquire(&thread_current()->parent_ledger->access_lock);
  thread_current()->parent_ledger->exit_code = status;
  lock_release(&thread_current()->parent_ledger->access_lock);

  lock_acquire(&file_lock);
  struct hash_iterator i;

  hash_first (&i, &thread_current()->file_map);
  while (hash_next (&i))
    {
      struct file_pair *f = hash_entry (hash_cur (&i), struct file_pair, elem);
      file_close(f->file);
    }

  lock_release(&file_lock);

  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

/* Runs executable cmd_line, passing arguments,
 * and retuns new process's pid.
 * Pass -1 to exit if program cannot load or run for ANY reason. */
void exec (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  const char *cmd_line = (const char *) args[0];

  validate_uaddr((const uint8_t *)cmd_line, 4);
  pid_t child_id = process_execute(cmd_line);
  f->eax = child_id;
  return;
}

/* Wait for child process.
 * Then retrieve child's exit status after termination and pass to exit.*/
void wait (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  int pid = (int) args[0];
  f->eax = process_wait(pid);
  return;
}

/* Create a new file with given name which is initial_size bytes in size.
 * Pass creation status to exit. */
void create (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 2);
  const char *file = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1];

  check_file_name(file);
  validate_uaddr((const uint8_t *)file, 4);
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);

  f->eax = success;
  return;
}

/* Delete the file with given name.
 * Pass deletion status to exit. */
void remove (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  const char *file = (const char *) args[0];

  check_file_name(file);
  validate_uaddr((const uint8_t *)file, 4);
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);

  f->eax = success;
  return;
}

/* Opens the file with given name.
 * Pass file descriptor to exit if successful. */
void open (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  const char *file = (const char *) args[0];

  check_file_name(file);
  validate_uaddr((const uint8_t *)file, 4);

  lock_acquire(&file_lock);
  struct file *new_file = filesys_open(file);
  lock_release(&file_lock);

  if(new_file == NULL) {
    f->eax = -1;
    return;
  }

  int new_fd = get_fd();
  store_file(new_fd, new_file);
  f->eax = new_fd;
  return;
}

/* Pass file size for given file descriptor to exit. */
void filesize (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  int fd = (int) args[0];
  struct file *file = get_file(fd);

  lock_acquire(&file_lock);
  int size = file_length(file);
  lock_release(&file_lock);
  f->eax = size;
  return;
}

/* Read given number of bytes from a file.
 * Pass number of bytes actually read to exit.*/
void read (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 3);
  int fd = (int) args[0];
  void *buffer = (void *) args[1];
  unsigned length = (unsigned) args[2];

  validate_uaddr((const uint8_t *)buffer, length);

  if(fd == 0) {
    lock_acquire(&file_lock);
    unsigned i = 0;
    void *current_addr = buffer;
    bool res = true;

    while(i < length && (res = put_user(current_addr, input_getc())) == true) {
      i++;
    }

    lock_release(&file_lock);
    f->eax = i;
    return;
  }
  else {
    struct file *file = get_file(fd);
    lock_acquire(&file_lock);
    int bytes_read = file_read(file, buffer, length);
    lock_release(&file_lock);
    f->eax = bytes_read;
    return;
  }
}

/* Write given number of bytes to a file.
 * Pass number of bytes actually written to exit.*/
void write (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 3);
  int fd = (int) args[0];
  const void *buffer = (const void *) args[1];
  unsigned length = (unsigned) args[2];
  validate_uaddr((const uint8_t *)buffer, length);

  if(fd == 1) {
    putbuf(buffer, length);
    f->eax = length;
    return;
  }

  struct file *file = get_file(fd);
  lock_acquire(&file_lock);
  int bytes_read = file_write(file, buffer, length);
  lock_release(&file_lock);
  f->eax = bytes_read;
  return;
}

/* Set next byte to be read/written in an open file to a certain position.
 * Position expressed in bytes from beginning of file. */
void seek (struct intr_frame *f UNUSED, void *sp, int args[3])
{
  getArgs(sp, args, 2);
  int fd = (int) args[0];
  unsigned position = (unsigned) args[1];
  struct file *file = get_file(fd);

  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
}

/* Pass position of next byte to be read/written in an open file to exit.
 * Position expressed in bytes from beginning of file. */
void tell (struct intr_frame *f, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  int fd = (int) args[0];
  struct file *file = get_file(fd);

  lock_acquire(&file_lock);
  unsigned pos = file_tell(file);
  lock_release(&file_lock);
  f->eax = pos;
  return;
}

/* Close a given file descriptor.*/
void close (struct intr_frame *f UNUSED, void *sp, int args[3])
{
  getArgs(sp, args, 1);
  int fd = (int) args[0];
  struct file *file = get_file(fd);

  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);
  remove_file(fd);
}

/* Deny writes to files in use as executables.
 * Kepps file open as long as process is running.*/
void deny_write_executable(const char *file_name)
{
  check_file_name(file_name);
  lock_acquire(&file_lock);
  struct file *new_file = filesys_open(file_name);

  if(new_file == NULL) {
    lock_release(&file_lock);
    safe_exit(-1);
  }

  file_deny_write(new_file);
  lock_release(&file_lock);
  int new_fd = get_fd();
  store_file(new_fd, new_file);
}
