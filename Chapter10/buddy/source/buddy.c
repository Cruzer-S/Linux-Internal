#include "buddy.h"

#include <stdarg.h>

// STRUCT_DATA: buddy_allocator, free_area struct, bitmap, page memory
//              자료구조를 위한 메모리, 이후 init_memory() 에서 사용됨
#define STRUCT_DATA	(1 * 1024 * 1024) // 1 MiB

// GET_NR_PAGE(BUDDY, ADDR): ADDR 에 해당하는 페이지 번호(index)를 반환
#define GET_NR_PAGE(BUDDY, ADDR) (						\
	((byte *) (ADDR) - ((byte *) (BUDDY)->lmem_map[0].addr)) / PAGE_SIZE	\
)

// 현재 PTR 의 값을 반환하고, PTR 에 SIZE 를 더한다.
#define ALLOC_FROM_PTR(PTR, SIZE) (((PTR) += (SIZE)), (void *) ((PTR) - (SIZE)))

// MARK_USED(INDEX, ORDER, AREA):
//	INDEX 와 ORDER 를 참조하여 bitmap 에 page 사용 정보를 매핑한다.
// - INDEX: page 의 실제 index 값
// - ORDER: 현재 order
// - AREA: free_area_t 구조체
//
// - INDEX >> (1 + (ORDER)) 를 통해 해당 ORDER 에서의 bitmap 위치를 알아낸다.
//          -----------------------------------------------------------------
// USED(*)  | *   *   *   *   *   -   *   *   -   -   -   *   -   -   -   - |
// PAGE     | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
//          -----------------------------------------------------------------
// ORDER(0) |   0   |   0   |   1   |   0   |   0   |   1   |   0   |   0   |
//          -----------------------------------------------------------------
// ORDER(1) |       0       |       0       |     1 -> 0    |       0       |
//          -----------------------------------------------------------------
// ORDER(2) |               0               |               1               |
//          -----------------------------------------------------------------
// ORDER(3) |                               0                               |
//          -----------------------------------------------------------------
//  A 상단의 아스키 아트는 free_area[ORDER].map 을 도식화한 것이고,
//  V 하단의 아스키 아트는 free_area[ORDER].free_list 를 도식화한 것이다.
//  | 9 |
//  |...|
//  |...|
//  |...|
//  | 4 |
//  | 3 |
//  | 2 | <--> C
//  | 1 | <--> 8 (will remove)
//  | 0 | <--> 5 <--> A
//
// 위와 같은 상황에서 alloc_pages 를 통해 order 1 의 페이지 할당을 요청하면
// 이를 free_list[1] 에서 찾게 된다. 사용 가능한 free page 를 찾으면 
// 해당 page 를 반환하고 bitmap 수정을 위해 아래와 같이 매크로를 호출하게 된다.
//	MARK_USED(buddy->free_area[1], 8, 1);
// 위 매크로를 호출하게 되면 아래와 같이 치환된다:
//	bitmap_set(buddy->free_area[1].map, 8 >> (1 + 1), false);
//	bitmap_set(buddy->free_area[1].map, 2, false);
#define MARK_USED(AREA, INDEX, ORDER)						\
	bitmap_set((AREA)->map, (INDEX) >> (1 + (ORDER)), false)

#include <stdlib.h>	// malloc()
#include <stdbool.h>	// true, false
#include <limits.h>
#include <stdint.h>

#include <sys/mman.h>

#include "bitmap.h"

extern Bitmap __bitmap_create(uint64_t size, void *addr, int addr_size);
extern int __bitmap_calc_alloc_size(bool is_full_struct, uint64_t size);

typedef char byte;

// free page 를 관리하기 위한 구조체
struct free_area_t {
	struct list_head free_list;	// 사용 가능한 page 를 연결한 리스트
	Bitmap map;			/* 사용 가능한 page 를 알려주는 bitmap
	                                   이후 메모리 병합에 사용됨.         */
};

struct buddy_allocator {
	// 할당된 메모리 크기
	unsigned int mem_size;

	// page 구조체의 시작 주소
	struct page *lmem_map;

	// free_pages: 할당 가능한 페이지의 최대 개수
	// max_order: 요청 가능 order 의 최댓값
	unsigned long free_pages;
	unsigned long max_order;

	// free page 를 관리하기 위한 구조체
	struct free_area_t *free_area;
};

typedef struct buddy_allocator *allocator;

//------------------------------------------------------------------------------
// Local function prototype 
//------------------------------------------------------------------------------
static void *ready_for_memory(int memsize);
// void _show_free_order_list(struct buddy_allocator *buddy, int order);
static void free_pages_ok(allocator buddy, int idx);
static struct page *__alloc_pages(
		allocator buddy,
		unsigned int gfp_mask, unsigned int order
	);
static struct page *expand(
		struct page *page,
		unsigned long index,
		int low, int high,
		struct free_area_t *area
	);
static struct buddy_allocator *init_memory(int memsize);
static int cal_cur_order(unsigned long mem);

static int calc_gap(int order);
static int cprintf(const char *fmt, char chr, int width, ...);
//------------------------------------------------------------------------------
// Global function
//------------------------------------------------------------------------------
struct buddy_allocator *buddy_create(int memsize)
{
	unsigned int order_page, total_page, cur_order;
	allocator buddy;
	struct free_area_t *area;
	
	// buddy 구조체 완성
	buddy = init_memory(memsize);
	if (buddy == NULL)
		return NULL;

	// 현재 order - 1 을 cur_order 로 잡아 페이지를 할당
	cur_order = buddy->max_order - 1;

	// total: 전체 페이지의 크기
	// order: 현재 order 에서 만들 수 있는 페이지의 크기
	//        가령 order 가 3 이고 페이지 하나의 크기가 4 KiB 라면
	//        order_page 는 8 이 된다.
	total_page = buddy->free_pages;
	order_page = TOTAL_PAGES(PAGE_SIZE << cur_order);
	// 일반적으로 order_page 가 total_page 의 절반이 되나,
	// 전체 메모리가 너무 커서 최대 order (max_order) 로 표현 가능한 
	// 페이지의 수가 2 배를 넘는 경우엔 아래의 반복문에서 처리가 이뤄진다.

	// free_area list 에 최초의 page 등록
	area = &buddy->free_area[cur_order];
	list_add(&area->free_list, &buddy->lmem_map[0].list);

	// 남은 페이지를 등록, 일반적으로 한번 돌고 끝나지만
	// 전체 메모리가 너무 큰 경우 max_order 페이지가 여러 개
	// 등록될 수 있기 때문에 반복을 통해 페이지를 추가한다.
	for (int nr = 0; nr < total_page - order_page; nr += (1UL << cur_order)) 
	{
		int nr_next = nr + (1UL << cur_order);
		list_add(&area->free_list, &buddy->lmem_map[nr_next].list);
		MARK_USED(area, nr, cur_order);
	}
	
	return buddy;
}

void buddy_destroy(struct buddy_allocator *buddy)
{
	munmap(buddy, buddy->mem_size + STRUCT_DATA);
	printf("free allocated real memory.. \n");
}

struct page *buddy_page_alloc(
		struct buddy_allocator *buddy,
		unsigned int gfp_mask,
		unsigned int order
	)
{
	return __alloc_pages(buddy, gfp_mask, order);
}

void buddy_page_free(struct buddy_allocator *buddy, struct page *page)
{
	int i =	(
		((char *) page->addr - (char *) buddy->lmem_map[0].addr)
		>> PAGE_SHIFT
	);

	free_pages_ok(buddy, i);
}

void buddy_show_free_list(struct buddy_allocator *buddy, int order)
{
	struct free_area_t *area = &buddy->free_area[order];
	int total_page, find;

	if (buddy->max_order <= order)
		return ;	// invalid operation

	area = &buddy->free_area[order];

	total_page = TOTAL_PAGES(PAGE_SIZE << buddy->max_order);

	cprintf("order %d", total_page * (3 + 1) + 1, '-', order); puts("");
	
	for (int i = 0; i < total_page; i += 1 << order) {
		printf("|");

		find = -1;
		for (struct page *p = (struct page *) area->free_list.next,
				 *q = (struct page *) &area->free_list;
		     p != q;
		     p = (struct page *) p->list.next)
		{
			if (GET_NR_PAGE(buddy, p->addr) == i) {
				find = i;
				break;
			}
		}

		if (find == -1) cprintf("-", calc_gap(order), ' ');
		else		cprintf("%d", calc_gap(order), ' ', find);
	}

	printf("|\n");
	cprintf("%s", total_page * (3 + 1) + 1, '-', "");

	#undef cprintf
}
//------------------------------------------------------------------------------
// Local function
//------------------------------------------------------------------------------
// ready_for_memory: buddy system 을 위해 필요한 메모리를 할당.
static void *ready_for_memory(int memsize)
{
	byte *real_memory = mmap(
		0, memsize + STRUCT_DATA,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
	);

	printf("memory is ready, address is %p\n", real_memory);

	return real_memory;
}

static int cal_cur_order(unsigned long mem)
{
	// 메모리에 맞는 단일 페이지 크기를 탐색한다.
	for (int i = BUDDY_MAX_ORDER - 1; i >= 0; i--)
		// 딱 맞아 떨어지는 크기를 찾았다면 해당 ORDER 를 반환한다.
		if (mem == (PAGE_SIZE << i))
			return i;

	// ex) buddy 를 위한 물리 메모리로 64KiB 를 잡았고
	//     단일 페이지의 크기가 4KiB 라면,
	//     최대로 가질 수 있는 page 의 개수는 16 개(4KiB 만 할당 시)이고
	//     최소로 가질 수 있는 page 의 개수는 1개이면서, 그 크기는
	//     PAGE_SIZE << 3 이다. 따라서 ORDER 가 3 인 상태의 

	if (mem > (PAGE_SIZE << (BUDDY_MAX_ORDER - 1)))
		return BUDDY_MAX_ORDER;

	return -1;
}

struct buddy_allocator *init_memory(int memsize)
{
	struct buddy_allocator *buddy;
	byte *real_memory;

	// 요청한 메모리가 page 크기에 맞아 떨어지는지 확인
	if ((memsize <= 0) || (memsize % PAGE_SIZE) != 0) {
		printf("allocate size %d bytes, not permitted\t\n", memsize);
		return NULL;
	}

	// 메모리 동적 할당
	real_memory = ready_for_memory(memsize);
	if (real_memory == NULL)
		return NULL;
/*	buddy system 을 위한 메모리를 할당, 메모리는 아래와 같이 사용된다:
r-------T-----------T-------------T--------T-----T-------T-------T-----T-------7
| buddy | free_area | page struct | bitmap | ... | page0 | page1 | ... | pageN |
L-------^-----------^-------------^--------^-----^-------^-------^-----^-------J
	... 으로 표시한 영역은 STRUCT_DATA 이다.                              */
	// buddy 구조체 기본 데이터 초기화
	buddy = ALLOC_FROM_PTR(real_memory, sizeof(struct buddy_allocator));
	buddy->mem_size = memsize;
	buddy->max_order = cal_cur_order(buddy->mem_size);

	// free_area 구조체를 위한 공간 할당
	buddy->free_area = ALLOC_FROM_PTR(real_memory,
		sizeof(struct free_area_t) * buddy->max_order
	);

	// free_pages 계산, page 구조체를 위한 공간 마련
	buddy->lmem_map = ALLOC_FROM_PTR(real_memory,
		(sizeof(struct page) * TOTAL_PAGES(buddy->mem_size))
	);
	buddy->free_pages = TOTAL_PAGES(buddy->mem_size);

	printf("allocate memory, size %d bytes\t\n", buddy->mem_size);
	printf("total number of page: %ld\n", buddy->free_pages);

	// buddy 구조체 내의 free_area 자료구조의 초기화를 진행한다.
	// 각 order 의 list 초기화 및 bitmap 의 생성 및 초기화를 수행한다.
	for (int i = 0; i < buddy->max_order; i++) {
		unsigned long map_size, struct_size;

		INIT_LIST_HEAD(&buddy->free_area[i].free_list);

		map_size = (buddy->free_pages / 2) >> i;
		struct_size = __bitmap_calc_alloc_size(true, map_size);

		printf("order(%d). map_size: %lu\tstruct_size: %lu\n",
			i,	   map_size,      struct_size);

		buddy->free_area[i].map = __bitmap_create(
			map_size,
			ALLOC_FROM_PTR(real_memory, struct_size),
			struct_size
		);
		bitmap_clear(buddy->free_area[i].map);
	}

	// page 구조체의 addr 멤버 변수가 실제 빈 메모리를 가르키도록 한다.
	real_memory = (byte *) buddy + STRUCT_DATA;
	for (int i = 0; i < buddy->free_pages; i++)
		buddy->lmem_map[i].addr = ALLOC_FROM_PTR(
			real_memory, PAGE_SIZE
		);

	return buddy;
}

static struct page *expand(
		struct page *page,
		unsigned long index,
		int low, int high,
		struct free_area_t *area
	)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;
		list_add(&area->free_list, &page->list);
		MARK_USED(area, index, high);
		index += size;
		page += size;
	}
	
	return page;
}

static struct page *__alloc_pages(
		allocator buddy,
		unsigned int gfp_mask,
		unsigned int order
	)
{
	struct page *page;
	unsigned int curr_order = order;
	struct free_area_t *area = &buddy->free_area[order];

	struct list_head *head, *curr;

	do {
		head = &area->free_list;
		curr = head->next;

		if (curr != head) {
			unsigned long index;

			page = LIST_ENTRY(curr, struct page, list);
			list_del(curr);
			index = GET_NR_PAGE(buddy, (unsigned long) page->addr);

			if (curr_order != buddy->max_order - 1)
				MARK_USED(area, index, curr_order);

			buddy->free_pages -= (1UL << order);

			page = expand(
				/* page, index */
				page, index,
				/* low, high */
				order, curr_order,
				/* free area */
				area
			);

			page->order = order;

			return page;
		}

		curr_order++;
		area++;
	} while (curr_order < buddy->max_order);

	return NULL;
}

static void free_pages_ok(allocator buddy, int idx)
{
	unsigned long index, page_idx, mask;
	struct page *page;
	struct free_area_t *area;
	unsigned int order;

	page = &buddy->lmem_map[idx];
	order = buddy->lmem_map[idx].order;

	mask = (~0UL) << order;
	page_idx = GET_NR_PAGE(buddy, (unsigned long) page->addr);

	index = page_idx >> (1 + order);

	area = &buddy->free_area[order];
	buddy->free_pages -= mask;

	while (mask + (1 << (buddy->max_order - 1))) {
		if (area >= buddy->free_area + buddy->max_order) {
			printf("over free_area boundary\n");
			break;
		}

		if ( !bitmap_switch(area->map, index) )
			break;

		page = &buddy->lmem_map[((page_idx) ^ -mask)];

		list_del(&page->list);
		mask <<= 1;
		area++;
		index >>= 1;
		page_idx &= mask;
	}

	list_add(&area->free_list, &buddy->lmem_map[page_idx].list);
}

int cprintf(const char *fmt, char chr, int width, ...)
{
	char *fmtstr, *alignstr;
	int fmtlen, padlen, rem;
	va_list ap;

	va_start(ap, width);
		fmtlen = vsnprintf(NULL, 0, fmt, ap);
		fmtstr = malloc(fmtlen + 1);
		if(fmtstr == NULL)
			goto RETURN_ERR;

		vsprintf(fmtstr, fmt, ap);
	va_end(ap);

	padlen = (fmtlen >= width) ? 0 : width - fmtlen;
	rem    = padlen % 2;

	alignstr = malloc(fmtlen + padlen + 1);
	if (alignstr == NULL)
		goto FREE_FMT_STR;

	free(fmtstr); free(alignstr);
	return fmtlen + padlen;

FREE_FMT_STR:	free(fmtstr);
RETURN_ERR:	return -1;
}

static int calc_gap(int order)
{
	if (order <= 0)
		return 3;

	return calc_gap(order - 1) * 2 + 1;
}
