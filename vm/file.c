/* file.c: Implementation of memory backed file object (mmaped object). */

#include <round.h>
#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/mmu.h"

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    ASSERT(page != NULL);
    ASSERT(type == VM_FILE);
    struct file_lazy_aux *aux = (struct file_lazy_aux *) page->uninit.aux;

    struct file *fl_file        = aux->file;
    off_t        fl_offset      = aux->ofs;
    size_t       fl_read_bytes  = aux->read_bytes;
    size_t       fl_zero_bytes  = aux->zero_bytes;
    bool         fl_writable    = aux->writable;
    struct mmap_file* fl_mmap_f = aux->mmap_f;
    // int fl_ref_count = aux->ref_count;

    // 실제로 읽을 수 있는 바이트 수 계산 (파일 끝 고려)
    size_t file_len  = file_length(fl_file);
    size_t available = 0;
    if (fl_offset < file_len) {
        available = file_len - fl_offset;
        if (available > fl_read_bytes)
            available = fl_read_bytes;
    }

    // 파일에서 실제로 읽기
    off_t actually = file_read_at(fl_file, kva, available, fl_offset);
    if (actually != available) {
        return false;
    }

    // 남은 부분을 zero-fill
    memset(kva + available, 0, PGSIZE - available);

    /* Set up the handler */
    page->operations = &file_ops;

    /* file_page 구조로 정보 복사 (munmap/swap/write-back에서 필요) */
    struct file_page *file_page = &page->file;
    file_page->file       = fl_file;
    file_page->ofs        = fl_offset;
    file_page->read_bytes = available;      // 실제로 읽은 바이트 수!
    file_page->zero_bytes = PGSIZE - available;
    file_page->writable   = fl_writable;
    file_page->mmap_f = fl_mmap_f;
    // file_page->ref_count = fl_ref_count;

    return true;
}

/* Initialize the file backed page */
bool
file_backed_initializer_orig (struct page *page, enum vm_type type, void *kva) {
    ASSERT(page != NULL);
    ASSERT(type == VM_FILE);
    struct file_lazy_aux *aux = (struct file_lazy_aux *) page->uninit.aux;

    // 파일 seek은 thread-safe하지 않으므로 file_read_at을 사용!
	// TODO: 오작동 시 걍 seek 쓸 것.
    struct file *fl_file = aux->file;
    off_t fl_offset = aux->ofs;
    size_t fl_read_bytes = aux->read_bytes;
    size_t fl_zero_bytes = aux->zero_bytes;
	bool fl_writable = aux->writable;

    size_t file_len = file_length(fl_file);

    // 실제로 읽을 수 있는 양 계산
    size_t available = 0;
    if (fl_offset < file_len) {
        available = file_len - fl_offset;
        if (available > fl_read_bytes)
            available = fl_read_bytes;
    }
    // 파일에서 read_bytes만큼 읽기
    off_t actually = file_read_at(fl_file, kva, fl_read_bytes, fl_offset);
    if (actually != available)
    {
        return false;
    }
    // 나머지 영역을 zero-fill

    memset(kva + fl_read_bytes, 0, fl_zero_bytes);

	/* Set up the handler */

	page->operations = &file_ops;

    // file_page 구조로 필요한 정보를 복사

    struct file_page *file_page = &page->file;
    file_page->file = fl_file;
    file_page->ofs = fl_offset;
    file_page->read_bytes = fl_read_bytes;
    file_page->zero_bytes = fl_zero_bytes;
    file_page->writable = fl_writable;

    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;

	return lazy_load_segment(page, file_page);
}

/* Swap out the page by writeback contents to the file. (dirty일 경우) */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page = &page->file;
    uint64_t *pml4 = thread_current()->pml4;

    // Dirty & writable 시에만 write-back
    if (page->frame &&
        pml4_is_dirty(pml4, page->va) &&
        file_page->writable) {
        file_write_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->ofs);
        pml4_set_dirty(pml4, page->va, 0);
    }

    // 연결 해제
    if (page->frame) {
        page->frame->page = NULL;
        page->frame = NULL;
    }

    // 매핑 해제
    pml4_clear_page(pml4, page->va);

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out_orig (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	// dirty 시 동기화
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}

	// 상호간 연결 해제
	page->frame->page = NULL;
	page->frame = NULL;

	// pml4에서 clear
	pml4_clear_page(thread_current()->pml4, page->va);

	return true;
}

/* 파일 기반 페이지를 destroy.
    - 페이지가 dirty 상태라면 파일에 write-back.
    - 페이지 매핑을 해제.

   중요! 
    - 파일 닫기는 여기서 안함 (do_munmap로 ㄱㄱ).
    - 파일 구조체는 호출자가 해제! */
static void file_backed_destroy(struct page *page) {
    struct file_page *file_page = &page->file;
    uint64_t *pml4 = thread_current()->pml4;

    // Dirty이면 write-back
    if (page->frame && pml4_is_dirty(pml4, page->va) && file_page->writable) {
        file_write_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->ofs);
        pml4_set_dirty(pml4, page->va, 0);
    }

    // 매핑 해제
    pml4_clear_page(pml4, page->va);

    // 중요!!! 파일 닫기는 do_munmap (또는 mmap_file 관리)에서만 처리!
    // (여기서는 안함)
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy_orig (struct page *page) {
	struct file_page *file_page = &page->file;
    uint64_t *pml4 = thread_current()->pml4;
    // dirty면 write-back (frame이 존재할 때만)
    if (page->frame && pml4_is_dirty(pml4, page->va) && file_page->writable) {
        file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
        pml4_set_dirty(pml4, page->va, 0);
    }

    // 매핑 해제
    pml4_clear_page(pml4, page->va);

    // TODO: 파일 닫기는 필요 시 별도 refcount 관리
    // lazy-file 통과 여부, 여기서 주석 처리하면 통과함
//      (file_page->ref_count)--;
//      // 해당 파일을 참조 하고 있는 ref_count를 세어봅니다. 0이 되는경우 해당 파일의 원본이라고 전제하고 그제야 file_close가 진행됩니다.
// if (file_page->ref_count == 0) {
//     file_close(file_page->file);
//     free(file_page->ref_count);
//     file_page->file = NULL;
// }
}

/* Do the mmap */
/* Maps FILE[offset…offset+length) into user virtual address space starting
   exactly at ADDR.  Returns ADDR on success, NULL on failure. */
void* do_mmap (void *addr, size_t length, int writable,
                struct file *file, off_t offset) {
    struct thread *t = thread_current ();

    /* ---------- 1.  Quick validation of parameters ---------- */
    if (file == NULL || length == 0)                  return NULL;
    if (addr == NULL || pg_round_down (addr) != addr) return NULL;
    if (offset % PGSIZE != 0)                         return NULL;
    if (!is_user_vaddr (addr) ||
        !is_user_vaddr ((uint8_t *)addr + length-1))  return NULL;

    /* ---------- 2.  Check for overlap with existing pages --- */
    size_t page_cnt = DIV_ROUND_UP (length, PGSIZE);
    for (size_t i = 0; i < page_cnt; i++) {
        void *va = (uint8_t *)addr + i * PGSIZE;
        if (spt_find_page (&t->spt, va) != NULL)      return NULL;
    }

    /* ---------- 3.  Prepare bookkeeping object -------------- */
    struct mmap_file *mmap_f = malloc(sizeof *mmap_f);
    if (mmap_f == NULL)                               return NULL;
    mmap_f->mmap_id = t->next_mmap_id++;
    mmap_f->addr     = addr;
    mmap_f->length   = length;
    mmap_f->file     = file_reopen (file);            /* private ref */

    if (mmap_f->file == NULL) { free (mmap_f); return NULL; }

    /* ---------- 4.  Per-page lazy installation -------------- */
    size_t remaining = length;
    off_t  ofs       = offset;
    void  *va        = addr;

    for (size_t i = 0; i < page_cnt; i++, va += PGSIZE, ofs += PGSIZE) {
            size_t page_read = remaining >= PGSIZE ? PGSIZE : remaining;
            size_t page_zero = PGSIZE - page_read;

        struct file_lazy_aux *aux = malloc (sizeof *aux);
        if (aux == NULL) goto fail;

        aux->file       = mmap_f->file;
        aux->ofs        = ofs;
        aux->read_bytes = page_read;
        aux->zero_bytes = page_zero;
        aux->writable   = writable;
        aux->mmap_f     = mmap_f;
        // aux->ref_count = 

        if (!vm_alloc_page_with_initializer (VM_FILE, va,
                                             writable,
                                             lazy_load_segment, aux))
            goto fail;

        remaining -= page_read;
    }

    /* ---------- 5.  Success: insert bookkeeping, return ------ */
    list_push_back (&t->mmap_list, &mmap_f->elem);
    return addr;

/* ---------- 6.  Failure path: roll back everything ---------- */
fail:
    /* undo any pages already registered */
    for (void *undo = addr; undo < va; undo += PGSIZE) {
        struct page *p = spt_find_page (&t->spt, undo);
        if (p) spt_remove_page (&t->spt, p);
    }
    file_close (mmap_f->file);
    free (mmap_f);
    return NULL;
}


void *
do_mmap_orig (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
    struct thread* curr = thread_current();
    
	// 하자있는 요청 내용 차단
    if(pg_round_down(addr) != addr) return NULL;
    if(length == 0) return NULL;
    if(offset % PGSIZE != 0) return NULL;
    if(file == NULL) return NULL;
    if(is_kernel_vaddr(addr)) return NULL;
    if(is_kernel_vaddr(length)) return NULL;

    struct file *r_file = file_reopen(file);
    //   if(offset + length > file_length(r_file)) return NULL;

    if(addr == NULL) // called by NOT user
    {
        return NULL;
    }
    else // called by USER
    {

        void *start_addr = pg_round_down(addr);
        size_t page_cnt = (length + PGSIZE - 1) / PGSIZE;
        // int *ref_count = malloc(sizeof(int));
        // *ref_count = page_cnt;

        void *current_addr = start_addr;
        for (size_t i = 0; i < page_cnt; i++)
        {
            // 중복 페이지 체크 (해당 주소에 이미 어떤 페이지가 할당되어 있으면 바로 return NULL;)
            if (spt_find_page(&curr->spt, current_addr) != NULL) {
                file_close(r_file);
                return NULL;
            }

            // aux 구조체 생성
            struct file_lazy_aux *aux = malloc(sizeof(struct file_lazy_aux));
            aux->file = r_file;
            aux->ofs = offset + (i * PGSIZE);
            aux->read_bytes = length - (i * PGSIZE) < PGSIZE ? length - (i * PGSIZE) : PGSIZE;
            aux->zero_bytes = PGSIZE - aux->read_bytes;
            aux->writable = writable;
            // aux->ref_count = ref_count;
            // VM_FILE 페이지 생성
            if (!vm_alloc_page_with_initializer(VM_FILE, current_addr, writable, lazy_load_segment, aux)) {
                    current_addr = start_addr;
                    for (size_t j = 0; j < i; j++)
                    {
                        vm_dealloc_page(pml4_get_page(thread_current()->pml4, current_addr));
                        current_addr += PGSIZE;
                    }     
                file_close(r_file);
                // 만약 페이지를 4개 할당했는데 3번쨰에서 실패하면 1, 2번쨰를 다 정리해야한다.
                // 그럼 뭐 어떻게 해야해?.. current_addr 단위로 더하고있는데, 해당 내용으로 다시 찾아다가 지워야한다는거잖아요
                // https://www.perplexity.ai/search/about-pintos-4ADhN6AcRuWMJB2AGVzxSg#101

                return NULL;
            }
            current_addr += PGSIZE;
        }
    }
    return addr;
}


/* ----------------------------------------------------------------
 * Page–local cleanup for a VM_FILE page.
 * Flushes to disk if the page is both dirty and writable,
 * then deletes the page from the supplemental page table.
 * ---------------------------------------------------------------- */
static void
munmap_helper (struct supplemental_page_table *spt, struct page *page)
{
	struct file_page *fp   = &page->file;
	struct thread    *t    = thread_current ();
	uint64_t         *pml4 = t->pml4;

	/* Write-back if dirty & writable. */
	if (page->frame &&
	    pml4_is_dirty (pml4, page->va) &&
	    fp->writable)
	{
		file_write_at (fp->file, page->frame->kva,
		               fp->read_bytes, fp->ofs);
		pml4_set_dirty (pml4, page->va, 0);
	}

	/* Unmap from MMU, detach frame, remove from SPT. */
	if (page->frame)
	{
		page->frame->page = NULL;
		page->frame       = NULL;
	}
	pml4_clear_page (pml4, page->va);
	spt_remove_page (spt, page);
}

/* ----------------------------------------------------------------
 * Unmap an entire mapping that starts at ADDR (exact mmap base).
 * Looks up the bookkeeping object, cleans every page it covers,
 * closes the file once, unlinks & frees the mmap_file descriptor.
 * ---------------------------------------------------------------- */
void do_munmap (void *addr) { /* user virtual base that was returned by mmap() */

	struct thread *curr_t   = thread_current ();
	struct list   *lst = &curr_t->mmap_list;
	struct mmap_file *mmap_f = NULL;

	/* 1. Find the mmap_file descriptor that owns ADDR. */
	for (struct list_elem *e = list_begin (lst);
	     e != list_end (lst);
	     e = list_next (e))
	{
		struct mmap_file *m = list_entry (e, struct mmap_file, elem);
		if (m->addr == addr) { mmap_f = m; break; }
	}
	if (mmap_f == NULL)      /* not an mmap base → silently ignore */
		return;

	/* 2. Walk every page in the mapping and clean it. */
	size_t page_cnt = DIV_ROUND_UP (mmap_f->length, PGSIZE);
	void *curr_mmap_f_addr = mmap_f->addr;

	for (size_t i = 0; i < page_cnt; i++, curr_mmap_f_addr += PGSIZE) {
		struct page *page = spt_find_page (&curr_t->spt, curr_mmap_f_addr);
		if (page && page_get_type (page) == VM_FILE)
			munmap_helper (&curr_t->spt, page);
	}

	/* 3. Close file (private reference) and drop bookkeeping. */
	file_close (mmap_f->file);
	list_remove (&mmap_f->elem);
	free (mmap_f);
}


void munmap_helper_orig(struct supplemental_page_table *spt, struct page *page)
{
	struct file_page *file_page = &page->file;
    if(pml4_is_dirty(thread_current()->pml4, page->va))
    {
        file_write_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
    }

    if(page->frame)
    {
        page->frame->page = NULL;
        page->frame = NULL;
    }

    // maybe insert frame to frame table
	pml4_clear_page(thread_current()->pml4, page->va);
    spt_remove_page(spt, page);
}

/* Do the munmap */
void
do_munmap_orig (void *addr) {
 //   if(pg_round_down(addr) % PGSIZE != 0) return NULL;
    struct supplemental_page_table *spt = &thread_current()->spt;
    void *cur_addr = addr;

    struct page *page = spt_find_page(spt, cur_addr);
    if (page == NULL || page->operations->type != VM_FILE)
        return;
    struct file *target_file = page->file.file;
    munmap_helper(spt, page);
    // page remove from spt, maybe swap out?

    bool is_same_file = true;
    while(is_same_file)
    {
        cur_addr += PGSIZE;
        struct page *search_page = spt_find_page(spt, cur_addr);
        if(search_page == NULL || search_page->operations->type != VM_FILE || search_page->file.file != target_file)
        {
            is_same_file = false;
            break;
        }
        munmap_helper(spt, search_page);
    }
}
