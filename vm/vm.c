/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/file.h"
#include "vm/inspect.h"
#include "userprog/process.h"
#include "kernel/hash.h"

#include "threads/vaddr.h"
#include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&g_frame_lock);
	list_init(&g_frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* 유틸, 헬퍼 ~ */
static inline bool is_target_stack(void* rsp, void* addr) {
    return addr != NULL
        && addr >= rsp - STACK_MAX_GAP
        && addr >= (void *)(USER_STACK - STACK_MAX_SIZE)
        && addr < (void *)USER_STACK;
}

static void vm_free_frame(struct frame *frame) {
	ASSERT(frame != NULL);

	lock_acquire(&g_frame_lock);
	
	list_remove(&frame->f_elem); // 프레임 테이블로부터 제거
	palloc_free_page(frame->kva); // 실제 프레임을 제거
	free(frame); // 할당했던 메모리 free 

	lock_release(&g_frame_lock);
}

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry(p_, struct page, page_hashelem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED
){
	const struct page *a = hash_entry(a_, struct page, page_hashelem);
	const struct page *b = hash_entry(b_, struct page, page_hashelem);
	return a->va > b->va;
}

/* ~ 유틸, 헬퍼 */

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, //새로운 uninit 페이지 생성 + uninit_new()로 
		vm_initializer *init, void *aux) {
	// 참고: 여기서 enum vm_type type란, 얘가 미래에 될 타입.
	ASSERT (VM_TYPE(type) != VM_UNINIT); 

	struct supplemental_page_table *spt = &thread_current ()->spt; //초기화 SPT에 등록(중복 방지)

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) { //SPT(해시 테이블)에서 VA로 페이지 찾기
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		 
		// 새 페이지를 콜록
		struct page *page = (struct page *)calloc(1, sizeof(struct page));
		if (page == NULL)
			goto err;

		// 필드들 초기화
		bool (*page_initializer)(struct page *, enum vm_type, void *);
		switch (VM_TYPE(type)) {
		case VM_ANON:
			page_initializer = anon_initializer;
			uninit_new(page, upage, init, type, aux, page_initializer);
			break;
		case VM_FILE:
			page_initializer = file_backed_initializer;
			uninit_new(page, upage, init, type, aux, page_initializer);
			break;
		default:
			printf("정의되지 않은 VM_TYPE(type)!\n");
			goto err;
		}
		page->writable = writable;

		// hash_insert 대신 spt_insert_page 사용하게끔 수정 :
		bool is_inserted = spt_insert_page(spt, page);
		if (!is_inserted) {
			free (page);
			goto err;
		}

		return is_inserted;  /* success means “page reserved, no frame yet” */
	}
	/* 중복 페이지 생성 방지 */
	goto err;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va){
    ASSERT (spt != NULL);
	
    /* VA의 field set 기반으로 더미 struct page를 만듦 */
	struct page* page_p = (struct page *)malloc(sizeof(struct page));
	struct page* found_page = NULL;
    page_p->va = pg_round_down (va); // 페이지 경계에 맞도록 조정

    /* 해시 테이블을 조회 */
    struct hash_elem *e = hash_find (&spt->main_table, &page_p->page_hashelem);
    if (e != NULL){
		found_page = hash_entry (e, struct page, page_hashelem);
	}
	free(page_p);
    return found_page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt ,struct page *page) { //페이지를 SPT에 삽입(중복방지)
	int succ = true;
	// hash_insert 함수를 사용해서 spt에 넣을 물건 page를 던진다.
	// hash_insert는 적절한 위치를 탐색하고, 중복 탐색도 합니다. (중복은 삽입 안됩니다!)
	// insert_elem으로 삽입에 대한 핵심 로직이 이루어집니다.
	struct hash_elem *result = hash_insert(&spt->main_table, &page->page_hashelem);
	if(result != NULL) succ = false;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->main_table, &page->page_hashelem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
 	struct list_elem *e;
	lock_acquire(&g_frame_lock);
 	for (e = list_begin (&g_frame_table); e != list_end (&g_frame_table); e = list_next (e))
	{
   		struct frame *frame = list_entry (e, struct frame, f_elem);
		if(pml4_is_accessed(&thread_current()->pml4, frame->page->va))
			pml4_set_accessed(&thread_current()->pml4, frame->page->va, false);
		else
		{
			lock_release(&g_frame_lock);
			return frame;
		}
 	}
	
	for (e = list_begin (&g_frame_table); e != list_end (&g_frame_table); e = list_next (e))
	{
		struct frame *frame = list_entry (e, struct frame, f_elem);
		 if(!pml4_is_accessed(&thread_current()->pml4, frame->page->va))
		 {
			lock_release(&g_frame_lock);
			return frame;
		 }
	}
	lock_release(&g_frame_lock);
	return NULL;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	if(victim == NULL) return NULL;

	if(!swap_out(victim->page)) return NULL;
	pml4_clear_page(&thread_current()->pml4, victim->page->va);


	/* TODO: swap out the victim and return the evicted frame. */
	victim->page->frame = NULL;
	victim->page = NULL;
	// 이거 swap out이랑 루틴이 중복되는데 흠

	memset(victim->kva, 0, PGSIZE);
	return victim;
}

/* palloc()을 호출하고 프레임을 얻습니다. 사용 가능한 페이지가 없으면 페이지를 
 * 축출(evict)하고 반환합니다. 이 함수는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀
 * 메모리가 가득 차면, 이 함수는 프레임을 축출하여 사용 가능한 메모리 공간을 확보합니다.*/
static struct frame *
vm_get_frame (void) {
	void *kva = palloc_get_page(PAL_USER);
	struct frame *frame = NULL;

	/* 할당 실패 시 eviction policy 집행 */
	if (kva == NULL) {
		frame = vm_evict_frame();
	}

	if(frame == NULL)
	{
		frame = malloc(sizeof(struct frame));
		if(frame == NULL)
		{
			if(kva) palloc_free_page(kva);
			PANIC("struct frame 할당 실패!");
		}
	
	}

	frame->kva = kva;
	frame->page = NULL;

	// 전역 frame table에 등록
	lock_acquire(&g_frame_lock);
	list_push_back(&g_frame_table, &frame->f_elem);
	lock_release(&g_frame_lock);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *pg_addr = pg_round_down(addr);
    while (vm_alloc_page(VM_ANON, pg_addr, true)) {  // SPT에 페이지 추가
        struct page *pg = spt_find_page(&thread_current()->spt, pg_addr);
        vm_claim_page(pg_addr);  // 물리 메모리까지 할당
        pg_addr += PGSIZE;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	// 쓰기 제한이 걸린 페이지를 다뤄야해요
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;

	// 얼리 리턴
	// 아! 커널 쓰레드는 page fault 날 일 자체가 없다!
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;
	
	/* TODO: Validate the fault */
	// todo: 페이지 폴트가 스택 확장에 대한 유효한 경우인지를 확인해야 합니다.
	void *rsp = (f==NULL) ? (thread_current()->rsp) : (f->rsp); // user access인 경우 rsp는 유저 stack을 가리킨다.
	if (!user)			// kernel access인 경우 thread에서 rsp를 가져와야 한다.
		rsp = thread_current()->rsp;

	// 스택 확장으로 처리할 수 있는 폴트인 경우, vm_stack_growth를 호출
	if (is_target_stack(rsp,addr)) vm_stack_growth(addr);

	page = spt_find_page(spt, addr);
	if (page == NULL) return false;

		if (!not_present) {
			if (page && write && !page->writable) return false;  // 프로세스 종료시킴
			return false;  // 다른 권한 문제들
		}

	    if (vm_do_claim_page(page)) {
			// 핵심: write fault이고 writable 페이지라면 dirty 설정
			if (write && page->writable) {
				pml4_set_dirty(thread_current()->pml4, page->va, true);
			}
			return true;
		}
		
	return false;
}


/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	struct supplemental_page_table *spt = &thread_current()->spt;

	page = spt_find_page(spt, va);
	if (page == NULL) return false;
	return vm_do_claim_page(page);
}

static bool
vm_do_claim_page (struct page *page) {
	ASSERT (page != NULL);
	struct frame *frame = vm_get_frame ();
	if (frame == NULL)
		return false;

	frame->page = page;
	page->frame = frame;

	uint64_t *pml4 = thread_current()->pml4;
	void *upage = page->va;
	void *kpage = frame->kva;
	bool rw = page->writable;

	bool is_page_set = pml4_set_page(pml4, upage, kpage, rw);

	if (!is_page_set) {
		page->frame = NULL;
		frame->page = NULL;
		vm_free_frame(frame);
		return false;
	}

	//printf("vm_do_claim_page()의 pml4_set_page 결과 - %d\n",is_page_set);
	bool is_swapped_in = swap_in(page, frame->kva);
	//printf("vm_do_claim_page()의 swap_in 결과 - %d\n",is_swapped_in);

	return is_swapped_in;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt ) { //SPT 해시 테이블 초기화
	hash_init(&spt->main_table, page_hash, page_less, NULL);
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst,
									struct supplemental_page_table *src) {
    if (hash_empty(&src->main_table)) return true;

    struct hash_iterator i;
    hash_first(&i, &src->main_table);
    while (hash_next(&i)) {
        struct page *srcPage = hash_entry(hash_cur(&i), struct page, page_hashelem);
        enum vm_type type = page_get_type(srcPage);
        void *upage = srcPage->va;
        bool writable = srcPage->writable;

        if (type == VM_UNINIT) {
            // 만약 uninit도 복사하고 싶다면 아래와 같이 할 수 있음.
            // vm_initializer *init = srcPage->uninit.init;
            // void *aux = srcPage->uninit.aux;
            // vm_alloc_page_with_initializer(...);
        } 
        else if (type == VM_ANON) {
            // 익명 페이지 복사 (heap/stack 등)
            if (!vm_alloc_page(type, upage, writable)) return false;
            if (!vm_claim_page(upage)) return false;
            struct page *newPage = spt_find_page(dst, upage);
            if (srcPage->frame != NULL)
                memcpy(newPage->frame->kva, srcPage->frame->kva, PGSIZE);
        }
        else if (type == VM_FILE) {
            // 중요! file-backed page 복사 시 file_reopen 사용!
            struct file_page *src_fp = &srcPage->file;

            struct file_lazy_aux *aux = malloc(sizeof(struct file_lazy_aux));
            aux->file       = file_reopen(src_fp->file); // 반드시 reopen!
            aux->ofs        = src_fp->ofs;
            aux->read_bytes = src_fp->read_bytes;
            aux->zero_bytes = src_fp->zero_bytes;
            aux->writable   = src_fp->writable;
			aux->mmap_f = src_fp->mmap_f;

            if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable,
                                                lazy_load_segment, aux))
                return false;
            // 참고: *frame 복사 필요 없음. file-backed는 lazy-load로 충분.
        }
        // extra 과제 수행하려면 추가
    }
    return true;
}


bool
supplemental_page_table_copy_orig (struct supplemental_page_table *dst,
		struct supplemental_page_table *src ) {
	
	if(hash_empty(&src->main_table)) return true; // 복사할게 없네용 : true 반환
	struct hash_iterator i;
	hash_first (&i, &src->main_table);
	while (hash_next (&i))
	{
		struct page *srcPage = hash_entry(hash_cur (&i), struct page, page_hashelem);
		enum vm_type type = page_get_type(srcPage);
		void *upage = srcPage->va;
		bool writable = srcPage->writable;

		// VM_UNINIT 쪽 삽입을 허용을 안하는데 이 쪽 분기를 타겠냐고~
		if(type == VM_UNINIT)
		{
			//vm_initializer *init = srcPage->uninit.init;
			//void *aux = srcPage->uninit.aux;
		}
		else if(type == VM_ANON)
		{
			// VM_ANON 분기점 말고 VM_FILE까지 허용하면 mmap_inherit 작동 안함
			if(!vm_alloc_page(type, upage, writable)) return false;
			if(!vm_claim_page(upage)) return false;
			struct page *newPage = spt_find_page(dst, upage);
			if(srcPage->frame != NULL)
				memcpy(newPage->frame->kva, srcPage->frame->kva, PGSIZE);
		}
		
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
/* Destroys all pages in the supplemental page table. */
void supplemental_page_table_kill (struct supplemental_page_table *spt) {
	if (spt == NULL) return;

	struct hash_iterator i;
	hash_first(&i, &spt->main_table);
	while (hash_next(&i)) {
		struct page *page = hash_entry(hash_cur(&i), struct page, page_hashelem);
		ASSERT(page != NULL);

		// 페이지 타입에 맞게 destroy 호출
		if (page->operations){
			destroy(page);
		}
		// uninit 페이지는 aux를 직접 해제해야 함
		if (page_get_type(page) == VM_UNINIT && page->uninit.aux)
			free(page->uninit.aux);

		free(page);
	}
	hash_clear(&spt->main_table, NULL);
}

void
supplemental_page_table_kill_orig (struct supplemental_page_table *spt) {
	hash_clear(&spt->main_table, NULL);
	// temp. 좀더 정성껏 작성 할 것. 특히 파일 있는경우
}



// /* Copy supplemental page table from src to dst */
// /* Return false on the first allocation error – callers usually kill the child. */
// bool supplemental_page_table_copy (struct supplemental_page_table *dst,
//                               		struct supplemental_page_table *src) {
//     struct hash_iterator it;
//     hash_first (&it, &src->main_table);

//     /* On failure we clean up everything we have inserted so far. */
//     while (hash_next (&it))
//     {
//         struct page *src_pg = hash_entry (hash_cur (&it), struct page,
//                                           page_hashelem);

//         enum vm_type type   = page_get_type (src_pg);
//         void        *upage  = src_pg->va;
//         bool         wr     = src_pg->writable;

//         switch (VM_TYPE(type))
//         {
//             /* ---------- 1.  VM_UNINIT : replicate lazily ----------- */
//             case VM_UNINIT:
//             {
//                 struct uninit_page *u = &src_pg->uninit;

//                 /* Deep-copy aux if necessary (may be NULL). */
//                 void *aux_copy = NULL;
//                 if (u->aux != NULL)
//                 {
//                     aux_copy = malloc (u->aux_size);
//                     if (aux_copy == NULL) goto fail;
//                     memcpy (aux_copy, u->aux, u->aux_size);
//                 }

//                 if (!vm_alloc_page_with_initializer (u->type, upage, wr,
//                                                      u->init, aux_copy))
//                     goto fail;
//                 break;
//             }

//             /* ---------- 2.  VM_ANON : eager copy ------------------- */
//             case VM_ANON:
//             {
//                 /* Create a blank anon page then claim & copy contents. */
//                 if (!vm_alloc_page (type, upage, wr)      ) goto fail;
//                 if (!vm_claim_page (upage)                ) goto fail;

//                 struct page *dst_pg = spt_find_page (dst, upage);
//                 if (src_pg->frame != NULL && dst_pg->frame != NULL)
//                     memcpy (dst_pg->frame->kva,
//                             src_pg->frame->kva,
//                             PGSIZE);
//                 break;
//             }

//             /* ---------- 3.  VM_FILE : share contents, new file* ---- */
//             case VM_FILE:
//             {
//                 /* Duplicate file handle */
//                 struct file *child_file = file_reopen (src_pg->file.file);
//                 if (child_file == NULL) goto fail;

//                 /* Build a fresh aux for the child */
//                 struct file_lazy_aux *aux = malloc (sizeof *aux);
//                 if (aux == NULL) { file_close (child_file); goto fail; }

//                 aux->file       = child_file;
//                 aux->ofs        = src_pg->file.ofs;
//                 aux->read_bytes = src_pg->file.read_bytes;
//                 aux->zero_bytes = src_pg->file.zero_bytes;
//                 aux->writable   = wr;

//                 if (!vm_alloc_page_with_initializer (VM_FILE, upage, wr,
//                                                      lazy_load_segment, aux))
//                 {
//                     file_close (child_file);
//                     free (aux);
//                     goto fail;
//                 }
//                 /* If page already loaded in parent, load it eagerly in child. */
//                 if (src_pg->frame != NULL)
//                     vm_claim_page (upage);   /* claim will cause lazy loader */
//                 break;
//             }

//             default:
//                 /* Unknown type – treat as fatal. */
//                 goto fail;
//         }
//     }
//     return true;

// /* ------------- rollback on error ----------------- */
// fail:
//     /* Walk dst SPT and destroy every page we created so far. */
//     hash_first (&it, &dst->main_table);
//     while (hash_next (&it))
//     {
//         struct page *p = hash_entry (hash_cur (&it), struct page, page_hashelem);
//         vm_dealloc_page (p);
//     }
//     hash_clear (&dst->main_table, NULL);
//     return false;
// }
