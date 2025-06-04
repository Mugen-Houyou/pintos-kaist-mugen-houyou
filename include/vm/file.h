#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

// vm.h와 동일한 필드를 가져야 함.
struct file_page {
	struct file *file;
	off_t ofs;
	size_t read_bytes;
	size_t zero_bytes;
    bool writable; // for permission bit in page table
	// int ref_count;
	struct mmap_file* mmap_f;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);

// 내부 함수
static bool file_backed_swap_in(struct page *page, void *kva); // 디스크에서 프레임으로 다시 로드
static bool file_backed_swap_out(struct page *page); // 퇴출 - 프레임을 디스크로 내림
static void file_backed_destroy(struct page *page); // 페이지 제거 시 리소스 해제

#endif
