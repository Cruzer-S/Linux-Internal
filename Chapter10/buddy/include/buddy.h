#ifndef BUDDY_H__
#define BUDDY_H__

// for the MAP_ANONYMOUS macro
#define _GNU_SOURCE

#include "list.h"

#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

// PAGE_SHIFT: 페이지가 2 의 몇 승인지를 나타내는 매크로
// PAGE_SIZE:  실제 페이지의 크기
// - 현재 페이지 크기 = 2 ^ 12 byte = 4096 byte = 4 KiB
#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)

// BUDDY_MAX_ORDER: 최대 ORDER 의 크기
// - 현재 BUDDY_MAX_ORDER 는 10 이므로, 한번에 할당 가능한
//   최대 메모리는 4 MiB (2^10 x 4 KiB) 이다.
// BUDDY_MAX_PAGESIZE: 한번에 할당 가능한 연속된 페이지의 최대 크기
#define BUDDY_MAX_ORDER		10
#define BUDDY_MAX_PAGESIZE	(PAGE_SIZE << BUDDY_MAX_ORDER)

// TOTAL_PAGES(MEMSIZE): MEMSIZE 에서 할당 가능한 페이지의 개수
// - MEMSIZE 를 PAGE_SHIFT 만큼 right shift 한다는 것은...
//   => MEMSIZE 를 2 ^ PAGE_SHIFT 만큼 나누는 것고 동일
//   => MEMSIZE 를 PAGE 의 크기로 나누는 것과 동일
//   => 그러므로 이는 MEMSIZE 를 기준으로 할당 가능한 PAGE 의 개수를 의미
#define TOTAL_PAGES(MEMSIZE)	((MEMSIZE) >> PAGE_SHIFT)

typedef struct page {
	struct list_head list;	// free_area_t 구조체와 연결하기 위한 리스트
	unsigned long flags;	// nothing to do for now
	void *addr;		// page 의 실제 메모리 주소
	int order;		// 해당 페이지의 order
} *Page;

typedef struct buddy_allocator *Buddy;

// buddy allocator 생성 & 초기화, 해제 & 제거 함수
Buddy buddy_create(int memsize);
void buddy_destroy(Buddy buddy);

// 페이지 할당, 해제 함수
Page buddy_page_alloc(Buddy buddy, unsigned int gfp_mask, unsigned int order);
void buddy_page_free(Buddy buddy, Page page);

// 현재 buddy system 의 상태를 출력하는 함수
void buddy_show_status(struct buddy_allocator *buddy);

#endif
