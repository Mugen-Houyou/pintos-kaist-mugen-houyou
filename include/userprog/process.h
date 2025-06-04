#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include <list.h>

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_add_file(struct file *file_obj);
struct file *process_get_file_by_fd(int fd);
struct thread *process_get_child(int pid);
void process_close_file_by_id(int fd);
void argument_stack(char **argv, int argc, void **rsp) ;
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);



// Project 3. ~
bool lazy_load_segment(struct page *page, void *aux);

/**
 * 각 프로세스의 mmap()된 파일마다 하나씩 가져야 하는 구조체.
 */
struct mmap_file {
    void *addr; // 매핑 시작 주소
    size_t length; // 매핑 길이 (단위는 바이트)
    struct file *file; // 매핑된 파일의 포인터
    struct list_elem elem; // mmap 리스트용
    int mmap_id; // 이 매핑의 고유 식별자 (프로세스내 유일)
};
// ~ Project 3. 

#endif /* userprog/process.h */
