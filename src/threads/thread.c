#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <float.h>
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. Ordered by priority in
   descending order.*/
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
  void *eip;             /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;
fixed_point load_avg;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *running_thread(void);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static bool is_thread(struct thread *) UNUSED;
static void *alloc_frame(struct thread *, size_t size);
static void schedule(void);
void thread_schedule_tail(struct thread *prev);
static tid_t allocate_tid(void);
void update_thread_priority(struct thread *, void *);
void update_thread_recent_cpu(struct thread *, void *);
void free_file_hash_elem(struct hash_elem *e, void *aux UNUSED);
void free_ledger_hash_elem(struct hash_elem *e, void *aux UNUSED);

/* Checks whether or not thread is idle */
bool is_idle(struct thread *t) {
  return t == idle_thread;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */

void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  list_init(&ready_list);
  list_init(&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
  if (thread_mlfqs) {
    load_avg = int_to_fixed_point(0);
  }
}

unsigned file_hash_func (const struct hash_elem *e, void *aux UNUSED) {
  struct file_pair *pair = hash_entry(e, struct file_pair, elem);
  return hash_int(pair->fd);
}

bool file_less_func (const struct hash_elem *a, const struct hash_elem *b,
                      void *aux UNUSED)
{
  struct file_pair *pairA = hash_entry(a, struct file_pair, elem);
  struct file_pair *pairB = hash_entry(b, struct file_pair, elem);
  return pairA->fd < pairB->fd;
}

unsigned ledger_hash_func (const struct hash_elem *e, void *aux UNUSED) {
  struct child_parent_ledger *ledger = hash_entry(e, struct child_parent_ledger, elem);
  return hash_int(ledger->child_tid);
}

bool ledger_less_func (const struct hash_elem *a, const struct hash_elem *b,
                      void *aux UNUSED)
{
  struct child_parent_ledger *ledgerA = hash_entry(a, struct child_parent_ledger, elem);
  struct child_parent_ledger *ledgerB = hash_entry(b, struct child_parent_ledger, elem);
  return ledgerA->child_tid < ledgerB->child_tid;
}

/* Used to compare priority of threads so that they can be put into an ordered
   list. */
bool compare_priority(const struct list_elem *a, const struct list_elem *b,
                      void *aux UNUSED) {
  ASSERT(a != NULL && b != NULL);

  if(thread_mlfqs){
    return list_entry(a, struct thread, elem)->priority >
           list_entry(b, struct thread, elem)->priority;

  }

  return list_entry(a, struct thread, elem)->donated_priority >
         list_entry(b, struct thread, elem)->donated_priority;
}

/* Used to compare priority of semaphores so that they can be put into an ordered
   list in monitor conditions */
bool compare_priority_sema(const struct list_elem *a, const struct list_elem *b,
                      void *aux UNUSED) {
  ASSERT(a != NULL && b != NULL);

  struct semaphore_elem *sema_a = list_entry(a,struct semaphore_elem,elem);
  struct semaphore_elem *sema_b = list_entry(b,struct semaphore_elem,elem);

  struct list *wait_a = &sema_a->semaphore.waiters;
  struct list *wait_b = &sema_b->semaphore.waiters;

  struct thread *thread_a = list_entry(
                              list_min(wait_a, &compare_priority, NULL),
                              struct thread, elem);
  struct thread *thread_b = list_entry(
                              list_min(wait_b, &compare_priority, NULL),
                              struct thread, elem);

  if(thread_mlfqs){
    return thread_a->priority > thread_b->priority;
  }

  return thread_a->donated_priority > thread_b->donated_priority;
}
/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Returns the number of threads currently in the ready list */
size_t threads_ready(void) { return list_size(&ready_list); }

/* Calculate priority from formula in sub-section B.2. */
void update_thread_priority(struct thread * t, void * aux UNUSED) {
  ASSERT(thread_mlfqs);
  t->priority = PRI_MAX - fixed_point_to_int(div_i(t->recent_cpu, 4))
	  - (t->nice_value * 2);

  if (t->priority > PRI_MAX) {
    t->priority = PRI_MAX;
  } else if (t->priority < PRI_MIN) {
    t->priority = PRI_MIN;
  }
}

/* Calculate and update recent_cpu value from formula in sub-section B.3. */
void update_thread_recent_cpu(struct thread * t, void * aux UNUSED) {
  ASSERT(thread_mlfqs);
  fixed_point mul = mul_i(load_avg, 2);
  fixed_point coef = div_f(mul, add_i(mul,1));
  t->recent_cpu = add_i(mul_f(coef, t->recent_cpu), t->nice_value);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs) {
    if (strcmp(t->name, "idle")) {
      t->recent_cpu = add_i(t->recent_cpu, 1);
    }

    if (timer_ticks() % TIMER_FREQ == 0) {

      fixed_point f1 = div_i(int_to_fixed_point(59), 60);
      fixed_point f2 = div_i(int_to_fixed_point(1), 60);
      fixed_point p1 = mul_f(f1, load_avg);

      int ready_threads_num = list_size(&ready_list) + 1;

      if (thread_current() == idle_thread) {
      	ready_threads_num = 0;
      }

      fixed_point p2 = mul_i(f2, ready_threads_num);
      load_avg = add_f(p1, p2);
      thread_foreach(&update_thread_recent_cpu, NULL);
    }

    if (timer_ticks() % TIME_SLICE == 0) {
      thread_foreach(&update_thread_priority, NULL);
    }

  }

   /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE) {
    intr_yield_on_return();
  }
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority, thread_func *function,
                    void *aux) {
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();
  if (thread_mlfqs) {
    t->recent_cpu = thread_current() -> recent_cpu;
    update_thread_priority(t, NULL);
  } else {
    t->priority = priority;
  }

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack'
     member cannot be observed. */
  old_level = intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock(t);
  if (thread_get_priority() < priority) {
    thread_yield();
  }
  return tid;
}

/* Traverse current threads list of locks to find highest priority
   amongst threads waiting on it so that it can correctly set its
   donated priority. */
void receive_priority(void) {
  ASSERT(is_thread(thread_current()));
  ASSERT(!thread_mlfqs);
  ASSERT(!intr_context());

  thread_current()->donated_priority = thread_current()->priority;

  if (!list_empty (&thread_current()->lock_list)) {
    struct list_elem *e = list_head(&thread_current()->lock_list);

    while ((e = list_next (e)) != list_end (&thread_current()->lock_list)) {
      struct lock *curr_lock = list_entry (e, struct lock, elem);

      if (!list_empty(&curr_lock->semaphore.waiters)) {
        struct thread *top_thread = list_entry (
			  list_min(&curr_lock->semaphore.waiters, &compare_priority, NULL),
			  struct thread, elem);

        if (thread_current()->donated_priority < top_thread->donated_priority)
          thread_current()->donated_priority = top_thread->donated_priority;
        else
          thread_current()->donated_priority = thread_current()->donated_priority;
      }
    }
  }
}

/* Donates current threads priority recursively to threads it is waiting on, the
   threads those threads are waiting on, etc. for a maximum of 8 levels of
   recursion. */
void donate_priority(int curr_priority,
		     struct thread *holder,
		     int levels_remaining) {
  ASSERT(!thread_mlfqs);
  if (holder == NULL || levels_remaining <= 0)
    return;

  if (curr_priority > holder->donated_priority) {
    holder->donated_priority = curr_priority;
    donate_priority (curr_priority, holder->waiting_on, levels_remaining - 1);
  }
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  /* Insert by order so that ready_list is in descending order by priority. */
  list_insert_ordered(&ready_list, &t->elem, &compare_priority, NULL);

  t->status = THREAD_READY;
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread () plus a couple of sanity checks. See the big c
omment
   at the top of thread.h for details. */
struct thread *thread_current(void) {
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

void free_file_hash_elem(struct hash_elem *e, void *aux UNUSED) {
  struct file_pair *file_pair = hash_entry(e, struct file_pair, elem);
  free(file_pair);
}

void free_ledger_hash_elem(struct hash_elem *e, void *aux UNUSED) {
  struct child_parent_ledger *child_ledger = hash_entry (e, struct child_parent_ledger, elem);
  lock_acquire(&child_ledger->access_lock);
  child_ledger->parent_exited = true;

  // If child has exited then we don't need ledger anymore.
  if(child_ledger->child_exited) {
    lock_release(&child_ledger->access_lock);
    free(child_ledger);
  } else {
    lock_release(&child_ledger->access_lock);
  }
}

void free_resources(void) {
  struct thread *cur = thread_current();

  // Release Locks.
  struct list_elem *e = list_head (&cur->lock_list);
  while ((e = list_next (e)) != list_end (&cur->lock_list)) {
      struct lock *curr_lock = list_entry(e, struct lock, elem);
      lock_release(curr_lock);
    }

  // Destroys and frees file_map.
  hash_destroy(&cur->file_map, &free_file_hash_elem);
  hash_destroy(&cur->child_ledgers, &free_ledger_hash_elem);
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

  free_resources();

#ifdef USERPROG
  process_exit();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
  struct thread *cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());
  old_level = intr_disable();

  if (cur != idle_thread)
    /* Insert by order so that ready_list is in descending order by priority. */
    list_insert_ordered(&ready_list, &cur->elem, &compare_priority, NULL);

  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func *func, void *aux) {
  struct list_elem *e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
  enum intr_level old_level = intr_disable();
  thread_current()->priority = new_priority;
  if (!thread_mlfqs) {
    receive_priority();
  }
  intr_set_level(old_level);

  // Yields so that the thread with highest priority can be selected.
  thread_yield();
}

/* Returns the current thread's priority. */
int thread_get_priority(void) {

  if(thread_mlfqs){
    return thread_current()->priority;
  }

  return thread_current()->donated_priority;

  }

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) {
  ASSERT(thread_mlfqs);
  thread_current() -> nice_value = nice;
  update_thread_priority(thread_current(), NULL);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
  ASSERT(thread_mlfqs);
  return thread_current() -> nice_value;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
  ASSERT(thread_mlfqs);
  return fixed_point_to_int(mul_i(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
  ASSERT(thread_mlfqs);
  return fixed_point_to_int(mul_i(thread_current() -> recent_cpu, 100));
}

struct thread * get_thread_from_id(tid_t tid) {
  struct list_elem *e = list_head(&ready_list);
  while ((e = list_next(e)) != list_end(&ready_list)) {
    struct thread *curr_thread = list_entry (e, struct thread, elem);

    if(curr_thread->tid == tid) {
      return curr_thread;
    }
  }
  return NULL;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *running_thread(void) {
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread *t) {
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t *)t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  if (thread_mlfqs) {
    if (!strcmp(name, "main")) {
      t->nice_value = 0;
      t->recent_cpu = 0;
    } else {
      t->nice_value = thread_get_nice();
      t->recent_cpu = thread_current() -> recent_cpu;
    }
  } else {
      t->donated_priority = priority;
      /* Initialise list of locks thread holds. */
      list_init(&t->lock_list);
  }

  #ifdef USERPROG
    t->hash_initialised = false;
  #endif

  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);
  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *alloc_frame(struct thread *t, size_t size) {
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *next_thread_to_run(void) {
  if (list_empty(&ready_list))
    return idle_thread;
  else {
    // Pop front of list (thread with highest priority).
    struct list_elem *to_pop = list_min(&ready_list, &compare_priority, NULL);
    list_remove(to_pop);
    return list_entry(to_pop,struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_schedule_tail(struct thread *prev) {
  struct thread *cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
  if(!cur->hash_initialised) {
      hash_init(&cur->child_ledgers, &ledger_hash_func, &ledger_less_func, NULL);
      cur->hash_initialised = true;
  }
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it. It's not safe to call printf() until
   thread_schedule_tail() has completed. */
static void schedule(void) {
  struct thread *cur = running_thread();
  struct thread *next = next_thread_to_run();
  struct thread *prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
