#include "threads/thread.h"

#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "devices/timer.h"
#include "intrinsic.h"
#include "threads/fixed-point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list sleep_list;
static struct list all_list;
/* Idle thread. */
static struct thread* idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread* initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func*, void* aux);

static void idle(void* aux UNUSED);
static struct thread* next_thread_to_run(void);
static void init_thread(struct thread*, const char* name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

static bool sleep_list_order(const struct list_elem* e1, const struct list_elem* e2, void* aux);

static fixed_t load_avg;

static void mlfqs_update_priority(struct thread* t);
static void mlfqs_update_recent_cpu(struct thread* t);
static void mlfqs_update_load_avg(void);
static void mlfqs_update_recent_cpu_all(void);
static void mlfqs_update_priority_all(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread*)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

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

    /* Reload the temporal gdt for the kernel
     * This gdt does not include the user context.
     * The kernel will rebuild the gdt with user context, in gdt_init (). */
    struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1, .address = (uint64_t)gdt};
    lgdt(&gdt_ds);

    /* Init the globla thread context */
    lock_init(&tid_lock);
    list_init(&ready_list);
    list_init(&destruction_req);
    list_init(&all_list);

    load_avg = FP_CONST(0);
    /* Set up a thread structure for the running thread. */
    initial_thread = running_thread();
    init_thread(initial_thread, "main", PRI_DEFAULT);
    initial_thread->status = THREAD_RUNNING;
    initial_thread->tid = allocate_tid();

    list_init(&sleep_list);
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

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
    struct thread* t = thread_current();

    /* Update statistics. */
    if (t == idle_thread) idle_ticks++;
#ifdef USERPROG
    else if (t->pml4 != NULL)
        user_ticks++;
#endif
    else
        kernel_ticks++;

    if (thread_mlfqs) {
        if (t != idle_thread) t->recent_cpu = FP_ADD_MIXED(t->recent_cpu, 1);

        if (timer_ticks() % TIMER_FREQ == 0) {
            mlfqs_update_load_avg();
            mlfqs_update_recent_cpu_all();
        }

        if (timer_ticks() % 4 == 0) mlfqs_update_priority_all();
    }
    /* Enforce preemption. */
    if (++thread_ticks >= TIME_SLICE) intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
    printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks,
           kernel_ticks, user_ticks);
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
tid_t thread_create(const char* name, int priority, thread_func* function, void* aux) {
    struct thread* parent_t = thread_current();
    struct thread* t;
    tid_t tid;

    ASSERT(function != NULL);

    /* Allocate thread. */
    t = palloc_get_page(PAL_ZERO);
    if (t == NULL) return TID_ERROR;

    /* Initialize thread. */
    init_thread(t, name, priority);
    tid = t->tid = allocate_tid();

    if (thread_mlfqs) {
        t->nice = parent_t->nice;
        t->recent_cpu = parent_t->recent_cpu;
        mlfqs_update_priority(t);
    }

    /* Call the kernel_thread if it scheduled.
     * Note) rdi is 1st argument, and rsi is 2nd argument. */
    t->tf.rip = (uintptr_t)kernel_thread;
    t->tf.R.rdi = (uint64_t)function;
    t->tf.R.rsi = (uint64_t)aux;
    t->tf.ds = SEL_KDSEG;
    t->tf.es = SEL_KDSEG;
    t->tf.ss = SEL_KDSEG;
    t->tf.cs = SEL_KCSEG;
    t->tf.eflags = FLAG_IF;

#ifdef USERPROG
    t->my_entry = palloc_get_page(PAL_ZERO);
    sema_init(&t->my_entry->wait_sema, 0);
    t->my_entry->tid = tid;
    t->my_entry->wait = false;
    t->my_entry->exit_status = -1;
    list_push_front(&parent_t->child_list, &t->my_entry->child_elem);
#endif

    list_push_back(&all_list, &t->allelem);

    /* Add to run queue. */
    thread_unblock(t);

    return tid;
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
void thread_unblock(struct thread* t) {
    enum intr_level old_level;

    ASSERT(is_thread(t));

    old_level = intr_disable();
    ASSERT(t->status == THREAD_BLOCKED);
    t->status = THREAD_READY;
    list_push_front(&ready_list, &t->elem);
    intr_set_level(old_level);
    if (t->priority > thread_current()->priority) {
        if (intr_context())
            intr_yield_on_return();
        else
            thread_yield();
    }
}

/* Returns the name of the running thread. */
const char* thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread* thread_current(void) {
    struct thread* t = running_thread();

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

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
    ASSERT(!intr_context());

#ifdef USERPROG
    process_exit();
#endif

    /* Just set our status to dying and schedule another process.
       We will be destroyed during the call to schedule_tail(). */
    intr_disable();
    list_remove(&thread_current()->allelem);
    do_schedule(THREAD_DYING);
    NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
    struct thread* curr = thread_current();
    enum intr_level old_level;

    ASSERT(!intr_context());

    old_level = intr_disable();
    if (curr != idle_thread) list_push_front(&ready_list, &curr->elem);
    do_schedule(THREAD_READY);
    intr_set_level(old_level);
}

/// @brief
/// 현재 스레드를 지정된 시간까지 재운다.
/// 스레드는 sleep_list에 추가되고, wakeup_tick이 도달할 때까지 BLOCKED 상태로 전환된다.
///
/// @param wakeup_tick
/// 스레드가 다시 깨어날 시점의 절대 tick 값 (`timer_ticks() + ticks`)
void thread_sleep(int64_t wakeup_tick) {
    enum intr_level old_level = intr_disable();

    struct thread* cur_thread = thread_current();
    cur_thread->wakeup_tick = wakeup_tick;
    list_insert_ordered(&sleep_list, &cur_thread->elem, sleep_list_order, NULL);
    thread_block();

    intr_set_level(old_level);
}

/// @brief
/// 현재 시각(ticks)에 도달한 스레드들을 깨워 READY 상태로 전환한다.
/// (sleep_list의 맨 앞부터 검사하며, wakeup_tick이 아직 안 된 스레드는 남겨둔다.)
void wake_sleeping_threads(int64_t tick) {
    enum intr_level old_level = intr_disable();
    while (!list_empty(&sleep_list)) {
        struct thread* cur_thread = list_entry(list_front(&sleep_list), struct thread, elem);
        if (cur_thread->wakeup_tick > tick) break;
        list_pop_front(&sleep_list);
        thread_unblock(cur_thread);
    }
    intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
    if (thread_mlfqs) return;

    enum intr_level old_level = intr_disable();
    struct thread* t = thread_current();
    t->base_priority = new_priority;
    if (list_empty(&thread_current()->donor_list)) t->priority = new_priority;

    if (!list_empty(&ready_list) &&
        (new_priority <
         list_entry(list_max(&ready_list, thread_priority_max, NULL), struct thread, elem)
             ->priority))
        thread_yield();
    intr_set_level(old_level);
}

/* Returns the current thread's priority. */
int thread_get_priority(void) { return thread_current()->priority; }

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice) {
    ASSERT(nice >= -20 && nice <= 20);

    enum intr_level old_level = intr_disable();
    thread_current()->nice = nice;
    mlfqs_update_priority(thread_current());

    if (!list_empty(&ready_list)) {
        struct thread* max_ready =
            list_entry(list_max(&ready_list, thread_priority_max, NULL), struct thread, elem);
        if (thread_current()->priority < max_ready->priority) thread_yield();
    }
    intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
    enum intr_level old_level = intr_disable();
    int nice_val = thread_current()->nice;
    intr_set_level(old_level);
    return nice_val;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
    enum intr_level old_level = intr_disable();
    int load = FP_TO_INT_ROUND(FP_MUL_MIXED(load_avg, 100));
    intr_set_level(old_level);
    return load;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
    enum intr_level old_level = intr_disable();
    int recent = FP_TO_INT_ROUND(FP_MUL_MIXED(thread_current()->recent_cpu, 100));
    intr_set_level(old_level);
    return recent;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void* idle_started_ UNUSED) {
    struct semaphore* idle_started = idle_started_;

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
static void kernel_thread(thread_func* function, void* aux) {
    ASSERT(function != NULL);

    intr_enable(); /* The scheduler runs with interrupts off. */
    function(aux); /* Execute the thread function. */
    thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread* t, const char* name, int priority) {
    enum intr_level old_level;
    ASSERT(t != NULL);
    ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT(name != NULL);

    memset(t, 0, sizeof *t);
    t->status = THREAD_BLOCKED;
    strlcpy(t->name, name, sizeof t->name);
    t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void*);
    t->priority = priority;
    t->magic = THREAD_MAGIC;

    t->base_priority = priority;
    t->waiting_lock = NULL;
    list_init(&t->donor_list);

    t->nice = 0;
    t->recent_cpu = FP_CONST(0);
    old_level = intr_disable();
    intr_set_level(old_level);

#ifdef USERPROG
    list_init(&t->child_list);
#endif
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread* next_thread_to_run(void) {
    if (list_empty(&ready_list))
        return idle_thread;
    else {
        struct list_elem* max_elem = list_max(&ready_list, thread_priority_max, NULL);
        list_remove(max_elem);
        return list_entry(max_elem, struct thread, elem);
    }
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame* tf) {
    __asm __volatile(
        "movq %0, %%rsp\n"
        "movq 0(%%rsp),%%r15\n"
        "movq 8(%%rsp),%%r14\n"
        "movq 16(%%rsp),%%r13\n"
        "movq 24(%%rsp),%%r12\n"
        "movq 32(%%rsp),%%r11\n"
        "movq 40(%%rsp),%%r10\n"
        "movq 48(%%rsp),%%r9\n"
        "movq 56(%%rsp),%%r8\n"
        "movq 64(%%rsp),%%rsi\n"
        "movq 72(%%rsp),%%rdi\n"
        "movq 80(%%rsp),%%rbp\n"
        "movq 88(%%rsp),%%rdx\n"
        "movq 96(%%rsp),%%rcx\n"
        "movq 104(%%rsp),%%rbx\n"
        "movq 112(%%rsp),%%rax\n"
        "addq $120,%%rsp\n"
        "movw 8(%%rsp),%%ds\n"
        "movw (%%rsp),%%es\n"
        "addq $32, %%rsp\n"
        "iretq"
        :
        : "g"((uint64_t)tf)
        : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void thread_launch(struct thread* th) {
    uint64_t tf_cur = (uint64_t)&running_thread()->tf;
    uint64_t tf = (uint64_t)&th->tf;
    ASSERT(intr_get_level() == INTR_OFF);

    /* The main switching logic.
     * We first restore the whole execution context into the intr_frame
     * and then switching to the next thread by calling do_iret.
     * Note that, we SHOULD NOT use any stack from here
     * until switching is done. */
    __asm __volatile(
        /* Store registers that will be used. */
        "push %%rax\n"
        "push %%rbx\n"
        "push %%rcx\n"
        /* Fetch input once */
        "movq %0, %%rax\n"
        "movq %1, %%rcx\n"
        "movq %%r15, 0(%%rax)\n"
        "movq %%r14, 8(%%rax)\n"
        "movq %%r13, 16(%%rax)\n"
        "movq %%r12, 24(%%rax)\n"
        "movq %%r11, 32(%%rax)\n"
        "movq %%r10, 40(%%rax)\n"
        "movq %%r9, 48(%%rax)\n"
        "movq %%r8, 56(%%rax)\n"
        "movq %%rsi, 64(%%rax)\n"
        "movq %%rdi, 72(%%rax)\n"
        "movq %%rbp, 80(%%rax)\n"
        "movq %%rdx, 88(%%rax)\n"
        "pop %%rbx\n"  // Saved rcx
        "movq %%rbx, 96(%%rax)\n"
        "pop %%rbx\n"  // Saved rbx
        "movq %%rbx, 104(%%rax)\n"
        "pop %%rbx\n"  // Saved rax
        "movq %%rbx, 112(%%rax)\n"
        "addq $120, %%rax\n"
        "movw %%es, (%%rax)\n"
        "movw %%ds, 8(%%rax)\n"
        "addq $32, %%rax\n"
        "call __next\n"  // read the current rip.
        "__next:\n"
        "pop %%rbx\n"
        "addq $(out_iret -  __next), %%rbx\n"
        "movq %%rbx, 0(%%rax)\n"  // rip
        "movw %%cs, 8(%%rax)\n"   // cs
        "pushfq\n"
        "popq %%rbx\n"
        "mov %%rbx, 16(%%rax)\n"  // eflags
        "mov %%rsp, 24(%%rax)\n"  // rsp
        "movw %%ss, 32(%%rax)\n"
        "mov %%rcx, %%rdi\n"
        "call do_iret\n"
        "out_iret:\n"
        :
        : "g"(tf_cur), "g"(tf)
        : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void do_schedule(int status) {
    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(thread_current()->status == THREAD_RUNNING);
    while (!list_empty(&destruction_req)) {
        struct thread* victim = list_entry(list_pop_front(&destruction_req), struct thread, elem);
        palloc_free_page(victim);
    }
    thread_current()->status = status;
    schedule();
}

static void schedule(void) {
    struct thread* curr = running_thread();
    struct thread* next = next_thread_to_run();

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(curr->status != THREAD_RUNNING);
    ASSERT(is_thread(next));
    /* Mark us as running. */
    next->status = THREAD_RUNNING;

    /* Start new time slice. */
    thread_ticks = 0;

#ifdef USERPROG
    /* Activate the new address space. */
    process_activate(next);
#endif

    if (curr != next) {
        /* If the thread we switched from is dying, destroy its struct
           thread. This must happen late so that thread_exit() doesn't
           pull out the rug under itself.
           We just queuing the page free reqeust here because the page is
           currently used by the stack.
           The real destruction logic will be called at the beginning of the
           schedule(). */
        if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
            ASSERT(curr != next);
            list_push_back(&destruction_req, &curr->elem);
        }

        /* Before switching the thread, we first save the information
         * of current running. */
        thread_launch(next);
    }
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

/// @brief
/// 두 스레드의 wakeup_tick 값을 비교하여 정렬 순서를 결정한다.
/// (timer_sleep에서 list_insert_ordered()에 사용됨)
///
/// @param e1 첫 번째 리스트 요소의 포인터
/// @param e2 두 번째 리스트 요소의 포인터
/// @param aux 추가 인자(사용하지 않음)
/// @return
/// e1의 wakeup_tick이 e2보다 작으면 true, 아니면 false
static bool sleep_list_order(const struct list_elem* e1, const struct list_elem* e2, void* aux) {
    struct thread* thread1 = list_entry(e1, struct thread, elem);
    struct thread* thread2 = list_entry(e2, struct thread, elem);
    return thread1->wakeup_tick < thread2->wakeup_tick;
}

bool thread_priority_max(const struct list_elem* e1, const struct list_elem* e2, void* aux) {
    struct thread* thread1 = list_entry(e1, struct thread, elem);
    struct thread* thread2 = list_entry(e2, struct thread, elem);
    return thread1->priority <= thread2->priority;
}

static void mlfqs_update_priority(struct thread* t) {
    if (t == idle_thread) return;

    /* priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
    int new_priority = FP_TO_INT_ZERO(
        FP_SUB_MIXED(FP_SUB(FP_CONST(PRI_MAX), FP_DIV_MIXED(t->recent_cpu, 4)), 2 * t->nice));

    if (new_priority > PRI_MAX)
        new_priority = PRI_MAX;
    else if (new_priority < PRI_MIN)
        new_priority = PRI_MIN;

    t->priority = new_priority;
}

static void mlfqs_update_recent_cpu(struct thread* t) {
    if (t == idle_thread) return;

    /* recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice */
    fixed_t coeff = FP_DIV(FP_MUL_MIXED(load_avg, 2), FP_ADD_MIXED(FP_MUL_MIXED(load_avg, 2), 1));

    t->recent_cpu = FP_ADD_MIXED(FP_MUL(coeff, t->recent_cpu), t->nice);
}

static void mlfqs_update_load_avg(void) {
    /* load_avg = (59/60)*load_avg + (1/60)*ready_threads */
    int ready_threads = list_size(&ready_list);
    if (thread_current() != idle_thread) ready_threads++;

    fixed_t term1 = FP_MUL(FP_DIV_MIXED(FP_CONST(59), 60), load_avg);
    fixed_t term2 = FP_MUL_MIXED(FP_DIV_MIXED(FP_CONST(1), 60), ready_threads);
    load_avg = FP_ADD(term1, term2);
}
static void mlfqs_update_recent_cpu_all(void) {
    struct list_elem* e;
    for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
        struct thread* t = list_entry(e, struct thread, allelem);
        mlfqs_update_recent_cpu(t);
    }
}

static void mlfqs_update_priority_all(void) {
    struct list_elem* e;
    for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
        struct thread* t = list_entry(e, struct thread, allelem);
        mlfqs_update_priority(t);
    }
}
