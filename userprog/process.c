#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "vm/vm.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void process_init (void) {
	struct thread *curr = thread_current ();

	// Project 3. ~
    list_init(&curr->mmap_list);
	curr->next_mmap_id = 1;
	// ~ Project 3.
}

// 파일 객체에 대한 파일 디스크립터를 생성, 프로세스에 추가, 해당 fd 리턴
int process_add_file(struct file *file_obj){
	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	int fd = curr->next_fd; // fd값은 2부터 출발
	
	while (curr->fd_table[fd] != NULL && fd < FDCOUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDCOUNT_LIMIT) {
		return -1;
	}

	curr->next_fd = fd;
	fdt[fd] = file_obj;

	return fd;
}

// 파일 객체를 검색
struct file *process_get_file_by_fd(int fd){
	if (fd < 2 || fd >= FDCOUNT_LIMIT)
		return NULL; // 범위외: NULL

	struct file **fdt = thread_current()->fd_table;
	return fdt[fd]; // fd에 대응되는 file object
}

// 자식 리스트에서 원하는 프로세스를 검색
struct thread *process_get_child(int pid) {
    struct thread *curr = thread_current();
    struct list *child_list = &curr->child_list; // 현재 스레드의 자식 리스트에 접근

    for (struct list_elem *e = list_begin(child_list); // 리스트의 첫 번째 요소부터 시작
		e != list_end(child_list);                    // 리스트의 끝에 도달할 때까지
		e = list_next(e)                             // 다음 요소로 이동
	){// ↑ 즉, 자식 리스트의 모든 요소를 순회
        // 현재 리스트 요소(e)를 포함하는 thread 구조체의 주소를 가져옴
		struct thread *this_t = list_entry(e, struct thread, child_elem); // (child_elem 멤버를 통해 역추적)
		// printf("this_t: [%p]",this_t);
        // 현재 스레드의 PID가, 찾는 PID와 일치?
        if (this_t->tid == pid) 
            return this_t; // 일치하면 해당 스레드를 리턴.
        
    }
    return NULL; // 못 찾았으니 NULL를 리턴.
}

// 현재 스레드의 fdt로부터 해당 fd의 파일 객체를 제거
void process_close_file_by_id(int fd){
	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	if (fd < 2 || fd >= FDCOUNT_LIMIT)
		return NULL;

	fdt[fd] = NULL;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);
	
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}
#include "threads/thread.h"  // (child_list, struct thread 등 선언 포함)

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/

    // intr_frame 복사
	struct thread *curr = thread_current();
	memcpy(&curr->parent_if, if_, sizeof(struct intr_frame)); // TODO: 스택에 넣지 말고 PALLOC로 확보하는 방향으로.
	
    // 자식 생성 시 부모를 넘김
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr);
	if (tid == TID_ERROR)
		return TID_ERROR;

    struct thread *child = process_get_child(tid);
    sema_down(&child->load_sema); // 자식의 로딩 완료까지 동기화 대기

    // 자식 로드 실패(exit_status == -2) 시 cleanup
    if (child->exit_status == -2) {
        // list_remove(&child->child_elem);
        sema_up(&child->exit_sema);
        return TID_ERROR;
    }

    return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
		return true;

	/* Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page(parent->pml4, va);

	// 만약 매핑된 페이지가 없다면(아마 optional)
	if (parent_page == NULL)
		return false;

	/* TODO: Allocate new PAL_USER page for the child and set result to NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false; // Out of memory: false 반환

	/* TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE according to the result). */
	memcpy(newpage, parent_page, PGSIZE); // PGSIZE=4096, 한 페이지 전체 복제
	writable = is_writable(pte); // pte에서 writable 비트 검사

	/* Add new page to child's page table at address VA with WRITABLE permission. */
	if (!pml4_set_page(current->pml4, va, newpage, writable))
		/* TODO: if fail to insert page, do error handling. */
		// 실패 시 메모리 해제 후 false 반환
		// palloc_free_page(newpage);
		return false;
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork (void *aux) { // 여기서 aux가 부모.
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	
	struct intr_frame *parent_if = &parent->parent_if; /* somehow pass the parent_if. (i.e. process_fork()'s if_) */
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
    /**주의: if_.R.rax = 0;는 반드시 필요.
     * 이유:
     *  부모 프로세스의 fork()는 자식의 pid를 리턴하나,
     *  자식 프로세스의 fork() 리턴값은 0이 되어야 한다. (UNIX/POSIX fork 규약과 동일)
     *  따라서, 자식에서 실행되는 코드(여기 __do_fork)에서는
     *  rax 레지스터를 0으로 설정하여 '자식 프로세스임'을 알린다.
    */
	if_.R.rax = 0;
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	// 파일 디스크립터 테이블 복제
	for (int i = 0; i < FDCOUNT_LIMIT; i++) {
		struct file *file = parent->fd_table[i];
		if (file == NULL)
			continue;
		if (file > 2)
			file = file_duplicate(file);
		current->fd_table[i] = file;
	}
	current->next_fd = parent->next_fd;

	sema_up(&current->load_sema); // 자식 동기화 대기 해제
	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ){
		do_iret (&if_);
	}

error:
	// thread_exit ();
	// current->exit_status = -2;
	sema_up(&current->load_sema);
	exit(-2);
}

void argument_stack(char **argv, int argc, void **rsp) {
	// Save argument strings (character by character)
	for (int i = argc - 1; i >= 0; i--) {
		int argv_len = strlen(argv[i]);
		for (int j = argv_len; j >= 0; j--) {
			char argv_char = argv[i][j];
			(*rsp)--;
			**(char **)rsp = argv_char; // 1 byte
		}
		argv[i] = *(char **)rsp; 		// 리스트에 rsp 주소 넣기
	}

	// Word-align padding
	int pad = (int)*rsp % 8;
	for (int k = 0; k < pad; k++) {
		(*rsp)--;
		**(uint8_t **)rsp = 0;
	}

	// Pointers to the argument strings
	(*rsp) -= 8;
	**(char ***)rsp = 0;

	for (int i = argc - 1; i >= 0; i--) {
		(*rsp) -= 8;
		**(char ***)rsp = argv[i];
	}

	// Return address
	(*rsp) -= 8;
	**(void ***)rsp = 0;
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/*-- Project 2. User Programs 과제 --*/
	// for argument parsing
    char *parse[64]; // 파싱된 문자열(토큰)들을 저장
    char *token, *save_ptr; // token: 현재 파싱된 문자열, save_ptr: strtok_r의 내부 상태 유지를 위한 포인터
    int count = 0; // 파싱된 문자열의 개수
		
    for (token = strtok_r(file_name, " ", &save_ptr); // file_name(例: "ls -a -l")에서 첫 번째 공백(" ")을 기준으로 문자열을 자르고, 첫 번째 토큰("ls")을 token에 할당.
		token != NULL; 								 // token이 NULL이 아닐 때까지 (더 이상 자를 문자열이 없을 때까지).
		token = strtok_r(NULL, " ", &save_ptr)      // 다음 공백(" ")을 기준으로 문자열을 잘라, 다음 토큰을 token에 할당 (NULL을 넣어 이전 호출의 다음 지점부터 계속 파싱).
	){
        parse[count++] = token;
	}
	/*-- Project 2. User Programs 과제 --*/

	/* And then load the binary */
	success = load (file_name, &_if);
    /* If load failed, quit. */
    if (!success){
    	palloc_free_page(file_name);
        return -1;
	}

    //  Project 2. User Programs의 Argument Passing ~
    argument_stack(parse, count, &_if.rsp); // 함수 내부에서 parse와 rsp의 값을 직접 변경하기 위해 주소 전달.
    _if.R.rdi = count; // 첫 번째 인자: argc, 즉 프로그램에 전달된 인자의 개수를 레지스터 rdi에 저장 (시스템 V AMD64 ABI 규약???).
    _if.R.rsi = (char *)_if.rsp + 8; // 두 번째 인자: argv. 스택의 첫 8바이트는 NULL이고, 그 다음 주소가 argv[0]이므로, rsp + 8이 argv 배열의 시작 주소.

    // hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true); // 디버그용. 유저 스택을 헥스 덤프로 출력.
    // ~  Project 2. User Programs의 Argument Passing

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */

	// struct thread *curr = thread_current();
	struct thread *child = process_get_child(child_tid);

	if (child == NULL)
		return -1;
	
	sema_down(&child->wait_sema); 
	int exit_status = child->exit_status;
	timer_msleep(1);
	list_remove(&child->child_elem);
	sema_up(&child->exit_sema);
	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	// printf("process_exit()!");
	for (int i = 2; i < FDCOUNT_LIMIT; i++) {
		if (curr->fd_table[i] != NULL)
			close(i);
	}
	palloc_free_multiple(curr->fd_table, FDT_PAGES);
	file_close(curr->running); // 현재 실행 중인 파일도 닫는다. load()에 있었던 걸 여기로 옮김.
	
    // mmap 해제
    struct list_elem *e = list_begin(&curr->mmap_list), *next;
    while (e != list_end(&curr->mmap_list)) {
        next = list_next(e);
        struct mmap_file *mf = list_entry(e, struct mmap_file, elem);
        do_munmap(mf->addr);
        e = next;
    }

	process_cleanup ();
	
	sema_up(&curr->wait_sema); // 대기 중이던 부모를 깨우기
	sema_down(&curr->exit_sema); // 자기 (부모의 시그널 대기)
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	// project 2. user programs - rox ~
	// 현재 스레드의 실행 중인 파일에 이 파일을 추가.
	t->running = file;

	// 지금 읽고 있는 실행 파일에 뭐 쓰면 안되니까.
	file_deny_write(file); // 해당 파일을 쓰기 금지로 등록
	// ~ project 2. user programs - rox

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file); // TODO: 여기 말고 process_exit에서 닫도록 해야.
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
bool lazy_load_segment (struct page *page, void *aux) {
    ASSERT(page != NULL);
    struct file_lazy_aux *fla = (struct file_lazy_aux *) aux;
    ASSERT(fla != NULL);

    uint8_t *kva = page->frame->kva;

    // 권한 기록
    page->writable = fla->writable;

    // file-backed 정보 page->file_page에 기록 (VM_FILE 타입만)
    if (page_get_type(page) == VM_FILE) {
        page->file.file = fla->file;
        page->file.ofs = fla->ofs;
        page->file.read_bytes = fla->read_bytes;
        page->file.zero_bytes = fla->zero_bytes;
        page->file.mmap_f = fla->mmap_f;
		// page->file.ref_count = fla->ref_count;
    }

    // 실제 파일로부터 읽기
    size_t file_len = file_length(fla->file);
    size_t available = 0;
    if (fla->ofs < file_len) {
        available = file_len - fla->ofs;
        if (available > fla->read_bytes)
            available = fla->read_bytes;
    }

    off_t actually = file_read_at(fla->file, kva, available, fla->ofs);

    if (actually != available) {
        free(fla); // malloc 해제
        return false;
    }

    // zero fill
    memset(kva + available, 0, PGSIZE - available);

    free(fla);
    return true;
}


/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct file_lazy_aux* fla = (struct file_lazy_aux *)malloc(sizeof(struct file_lazy_aux));
		fla->file = file;					 // 내용이 담긴 파일 객체
		fla->ofs = ofs;					 // 이 페이지에서 읽기 시작할 위치
		fla->read_bytes = page_read_bytes; // 이 페이지에서 읽어야 하는 바이트 수
		fla->zero_bytes = page_zero_bytes; // 이 페이지에서 read_bytes만큼 읽고 공간이 남아 0으로 채워야 하는 바이트 수
		fla->writable = writable;

		
			if (!vm_alloc_page_with_initializer (VM_ANON, upage,
				writable, lazy_load_segment, fla))
					return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;

		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack (struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

    // SPT에 anon page로 등록
    success = vm_alloc_page(VM_ANON, stack_bottom, true);
    if (!success)
        return false;

    // 바로 프레임 할당(클레임)
    success = vm_claim_page(stack_bottom);
    if (!success)
        return false;
	
    // rsp를 USER_STACK으로 세팅
    if_->rsp = USER_STACK;

    return success;
}
#endif /* VM */