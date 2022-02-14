#include "buddy.h"

#include "exstdlib.h"

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
	bitmap_switch((AREA)->map, (INDEX) >> (1 + (ORDER)))

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

//------------------------------------------------------------------------------
// Local function prototype 
//------------------------------------------------------------------------------
static int find_fitness_order(int memsize);
static struct page *expand(
		struct page *page,
		unsigned long index,
		int low, int high,
		struct free_area_t *area
	);
static struct buddy_allocator *init_memory(int memsize);
static int calc_gap(int order);
static void buddy_show_order_status(struct buddy_allocator *buddy, int order);

//------------------------------------------------------------------------------
// Global function
//------------------------------------------------------------------------------
struct buddy_allocator *buddy_create(int memsize)
{
	unsigned int order_page, total_page, cur_order;
	struct buddy_allocator *buddy;
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

// buddy allocator 를 제거한다.
// buddy 는 mmap 을 통해 할당받은 메모리를 적절히 쪼개 할당했으므로 munmap 
// 함수를 호출하는 것만으로 모든 buddy 시스템 데이터를 제거하는 것이 가능하다.
void buddy_destroy(struct buddy_allocator *buddy)
{
	munmap(buddy, buddy->mem_size + STRUCT_DATA);
	printf("free allocated real memory.. \n");
}

struct page *buddy_page_alloc(struct buddy_allocator *buddy, unsigned int order)
{
	struct page *page;
	unsigned int cur_order;
	struct free_area_t *area;

	struct list_head *head, *next;

	// 할당하려는 order 가 max_order 다 크다면 NULL 반환
	if (buddy->max_order <= order)
		return NULL;

	// free_area 가져오기
	cur_order = order;
	area = &buddy->free_area[cur_order];

	do {
		head = &area->free_list;
		next = head->next;

		// head 가 next 와 같지 않다? => 할당 가능한 페이지가 존재한다.
		if (next != head) {
			unsigned long index;

			/* 
			 * 1. list 에 연결되어 있는 페이지를 가져온다.
			 * 2. 해당 페이지를 연결 리스트에서 제거한다.
			 * 3. 페이지의 주소를 통해 페이지 인덱스를 가져온다.
			 */
			page = LIST_ENTRY(next, struct page, list);
			list_del(next);
			index = GET_NR_PAGE(buddy, (unsigned long) page->addr);

			// max_order 인 경우를 제외한 모든 경우에 MARK 한다.
			//if (cur_order != buddy->max_order - 1)
			MARK_USED(area, index, cur_order);

			// free_pages 를 할당한 크기만큼 줄인다.
			buddy->free_pages -= (1UL << order);

			page = expand(
				/* page, index */
				page, index,
				/* low, high */
				order, cur_order,
				/* free area */
				area
			);

			page->order = order;

			return page;
		}

		// cur_order 에서 페이지를 찾지 못하면 여기로 떨어져 내려온다.
		// cur_order 에 page 가 없다는 것은 아래를 뜻한다.
		// => free_area list 에 그 어떠한 페이지도 없다.
		// 따라서 다음 order 로 넘어간다.
		cur_order++;
		area++;

		// order 가 만약 max_order 보다 크다면?
		// => 이건 더 이상 할당할 페이지가 없다는 뜻
	} while (cur_order < buddy->max_order);

	// 그 어디에도 할당 가능한 데이터가 없다면 NULL 반환
	return NULL;
}

void buddy_page_free(struct buddy_allocator *buddy, struct page *page)
{
	unsigned long page_num, page_idx, mask;
	struct free_area_t *area;
	unsigned int order, index;

	page_num = (
		((char *) page->addr - (char *) buddy->lmem_map[0].addr)
		>> PAGE_SHIFT
	);

	page = &buddy->lmem_map[page_num];
	order = buddy->lmem_map[page_num].order;

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

void buddy_show_status(struct buddy_allocator *buddy,
		       enum buddy_show_type type)
{
	struct free_area_t *area;
	int total_page;
	int padd_bitmap, padd_freelist, padd_order;

	for (int i = 0; i < buddy->max_order; i++) {
		area = &buddy->free_area[i];

		total_page = TOTAL_PAGES(PAGE_SIZE << buddy->max_order);
		padd_bitmap = bitmap_size(area->map) / bitmap_bytebit() + 2
			    + bitmap_size(area->map);
		padd_freelist = total_page * (3 + 1) + 1;
		padd_order = 12;

		putchar('-'); cprintf(" [order] ", '-', padd_order);
		cprintf(" [free list] ", '-', padd_freelist);
		cprintf(" [bitmap] ", '-', padd_bitmap); NEWLINE;

		putchar('|'); cprintf("%d", ' ', padd_order, i); putchar('|');
		buddy_show_order_status(buddy, i);
		putchar(' '); bitmap_show(area->map, false); puts(" |");

		cprintf("", '-', padd_bitmap + padd_freelist + padd_order + 1);
		NEWLINE;
	}
}
//------------------------------------------------------------------------------
// Local function
//------------------------------------------------------------------------------
static int find_fitness_order(int memsize)
{
	// - 요청한 메모리가 단일 page 크기에 딱 맞아 떨어지는지 확인
	// - 최소 할당 단위가 PAGE_SIZE 이므로 당연히 PAGE_SIZE 로 정확하게
	//   나누어 떨어져야 한다. 그렇지 않다면 -1 반환.
	if ((memsize <= 0) || (memsize % PAGE_SIZE) != 0)
		return -1;

	// 메모리 크게에 적합한 max order 를 구한다.
	if (memsize <= (PAGE_SIZE << (BUDDY_MAX_ORDER - 1))) {
		for (int i = 0; i < BUDDY_MAX_ORDER; i++) {
			// mem_size 와 동일한 크기의 단일 page order 라면
			// 해당 값을 max_order 로 사용한다.
			if (memsize == (PAGE_SIZE << i))
				return i;

			if (memsize > (PAGE_SHIFT << i))
				return i;
		}
	}

	// mem_size 가 max_order 로 할당 가능한 최대 memory 크기보다 크다면
	// 당연히 max order 역시 BUDDY SYSTEM 의 MAX ORDER 로 잡는다.
	return BUDDY_MAX_ORDER;
}

static struct buddy_allocator *init_memory(int memsize)
{
	struct buddy_allocator *buddy;
	byte *real_memory;
	int max_order;

	// memsize 에 적합한 max_order 를 구한다.
	max_order = find_fitness_order(memsize);
	if (max_order < 0)
		return NULL;
	
	// 메모리 동적 할당
	real_memory = mmap(
		0, memsize + STRUCT_DATA,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
	);

	if (real_memory == NULL) {
		printf("failed to allocate %d size memory",
			memsize + STRUCT_DATA);
		return NULL;
	} else printf("memory is ready, address is %p\n", (void *) real_memory);

/*******************************************************************************
 * - buddy system 을 위한 메모리를 할당, 메모리는 아래와 같이 사용된다:        *
 *   r-------T-----------T-------------T--------T----T-----T-----T----T-----7  *
 *   | buddy | free_area | page struct | bitmap | .. | pg0 | pg1 | .. | pgN |  *
 *   L-------^-----------^-------------^--------^----^-----^-----^----^-----J  *
 ******************************************************************************/

	// buddy 구조체 기본 데이터 초기화
	buddy = ALLOC_FROM_PTR(real_memory, sizeof(struct buddy_allocator));
	buddy->mem_size = memsize;
	buddy->max_order = max_order;
	
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

		list_init(&buddy->free_area[i].free_list);

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

// buddy_page_free 에 의해 호출되는 함수로 현재 order 에서 할당 가능한 page 가
// 없는 경우 상위 free_area list 에서 할당 가능한 page 를 쪼개어 할당.
static struct page *expand(
		struct page *page,
		unsigned long index,
		int low, int high,
		struct free_area_t *area
	)
{
	unsigned long size = (1 << high);

	// high 는 현재 발견한 상위 free_area list 의 order 이고
	// low 는 현재 할당을 요청한 page 의 order 이다.
	// index 는 high order 에 존재하는 page 의 index 를 의미한다.
	while (high > low) {
		// 1. (area - 1) 은 하위 order 로 하강함을 의미한다.
		// 2. (high - 1) 역시 상위 order 를 하강함을 의미한다.
		// 3. size 역시 2 의 high order 승이므로 같이 맞춰 내린다.
		area--;
		high--;
		size >>= 1;

		// 여기에서 기존 page 를 하강한 free_area list 에 등록하는데
		// 이렇게 되면 page 의 크기만 반으로 줄어든다. 재미있는 점은
		// page 의 index 에는 아무런 변화가 일어나지 않는다는 것이다.
		list_add(&area->free_list, &page->list);

		// 하위 order 에 사용 가능한 page 두 개가 생겼고 (상위 order 의
		// page 를 한 단계 내렸기 때문에) 그 중 하나는 할당 혹은 다시 
		// 재귀적으로 쪼갤 것이기에 사용 중으로 표시한다.
		MARK_USED(area, index, high);

		// index 의 크기를 size 만큼 증가
		index += size;
		// 페이지의 역시 size index 만큼 뛰어 넘는다.
		page += size;
	}

	// 최종적으로 요청한 order 에 해당하는 page 를 반환한다.
	return page;

	// - 처음에는 위 코드의 동작 방식이 정확하게 이해되지 않을 수 있다.
	//   따라서, main 코드를 실행시켜 그 동작을 이해하는 것이 좋다.
	// - 최초 page 할당 시 어떠한 방식으로 page 가 쪼개지는지 주목하라.
}

// buddy_show_order_status() 에서 free_area list 간극을 계산하는 함수
static int calc_gap(int order)
{
	if (order <= 0)
		return 3;

	return calc_gap(order - 1) * 2 + 1;
}

// 현재 buddy allocator 의 비트맵 및 free_area list 의 정보를 상세히 출력한다.
static void buddy_show_order_status(struct buddy_allocator *buddy, int order)
{
	struct free_area_t *area;
	int total_page, find;

	if (buddy->max_order <= order)
		return ;

	area = &buddy->free_area[order];
	total_page = TOTAL_PAGES(PAGE_SIZE << buddy->max_order);

	for (int i = 0; i < total_page; i += ((1 << order)))
	{
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

		if (find == -1) cprintf("-", ' ', calc_gap(order));
		else		cprintf("%d", ' ', calc_gap(order), find);

		putchar('|');
	}
}
