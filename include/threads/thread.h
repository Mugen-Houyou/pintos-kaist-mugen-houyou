#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h" // Project 2. User Programs 구현

#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/*-- Project 2. User Programs 과제. --*/
// for system call
#define FDT_PAGES 2                       // FDT 할당을 위한 페이지수. (thread_create, process_exit 등)
#define FDCOUNT_LIMIT FDT_PAGES*(1 << 4)  // FD의 idx를 제한. 동료 리뷰 결과 보통 256-1536 정도의 값을 잡는 듯. 그러나 32 같은 적은 수에서도 multi-oom이 통과되어야 정상.
/*-- Project 2. User Programs 과제. --*/

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
	void *rsp; // 현재 액세스가 user인지 kernel인지 확인
	struct list mmap_list;
	int next_mmap_id;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
    
	/*-- Alarm clock 과제  --*/
	int64_t wakeup_tick; // Alarm clock 과제 - 어느 틱에 깨울지.
	/*-- Alarm clock 과제  --*/

	/*-- Priority donation 과제 --*/
	int original_priority;
    struct lock *wait_lock;
    struct list donations;
    struct list_elem donation_elem;
	/*-- Priority donation 과제 --*/

	/*-- Project 2. User Programs 과제 --*/
	int exit_status;
	struct file **fd_table;
	int next_fd;// fd테이블에 open spot의 인덱스

	struct intr_frame parent_if;
    struct list child_list;        // 자신의 자식 목록
    struct list_elem child_elem;   // 부모의 child_list에 들어갈 때 사용하는 노드

	struct semaphore load_sema; // 동기화 대기용 세마포어. 자식 프로세스가 load() 완료 후 부모에게 알리기 위함. fork() 직후 자식이 실행을 성공적으로 시작했는지 부모가 알기 위해 사용됨.
	struct semaphore exit_sema; // 자식 프로세스가 종료되었음을 부모가 확인할 수 있도록 하기 위한 세마포어
	struct semaphore wait_sema; // 부모가 자식의 종료를 기다릴 수 있도록 하기 위한 세마포어
 
	struct file *running; // 현재 실행 중인 파일
	/*-- Project 2. User Programs 과제 --*/
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

bool thread_priority_cmp(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool thread_wakeup_tick_cmp(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
