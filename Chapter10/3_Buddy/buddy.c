/********************************************************/
/*                                                      */
/* Project      : Buddy System                          */
/* File         : buddy.c                               */
/* Author       : Youn DaeSeok(woodsmano@gmail.com)     */
/* Company      : Dankook Univ. Embedded system lab.    */
/* Note         : buddy 할당 및 해제 루틴		*/
/* Date         : 2008.7.3                              */
/********************************************************/

#include "./Header/buddy.h"

unsigned int mem_size; //real memory size define...
//offset for mmap address space 
unsigned long mem_offset;
//unsigned int totalpage; //number of page define...

void* real_memory; //allocate by malloc
unsigned long free_pages;
int max_order; //support small than BUDDY_MAX_ORDER size;

free_area_t free_area[BUDDY_MAX_ORDER];
mem_map_t *lmem_map;


#define STRUCT_DATA		( 1 * 1024 * 1024 ) //for free_area bitmap, lmem_map

void show_bitmap(unsigned long value)
{
	if (value <= 0)
		return ;

	show_bitmap(value / 2);
	fputc(value % 2 == 0 ? '0' : '1', stdout);
}

void ready_for_memory( void )
{
	real_memory = mmap( 0, mem_size + STRUCT_DATA, 
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0 );
	printf( "memory is ready, address is %lx \n", (unsigned long)real_memory);
}

void* get_address_map( int size )
{
	char* addr;
	
	addr = (char *)((char *)real_memory + mem_offset);
	memset( addr,(int)0, size );
	mem_offset += size;

	return addr;
}

void mapping_page( mem_map_t *mem_map )
{
	unsigned long temp = mem_offset;
	while( mem_offset <= mem_size + STRUCT_DATA )
	{
		mem_map->addr = ( unsigned long *)((char *)real_memory + mem_offset);
		mem_offset += PAGE_SIZE;
		mem_map++;
	}
	mem_offset = temp;
}


static __inline__ int constant_test_bit( int nr, const volatile void* addr )
{
	 return ((1UL << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ void __change_bit( int nr, volatile void* addr )
{
	if( constant_test_bit(nr, addr) == 1){
		(((volatile unsigned int *) addr)[nr >> 5]) &= (0xFFFFFFFF ^ (1UL << (nr & 31)));
	}else{
		(((volatile unsigned int *) addr)[nr >> 5]) |= (1UL << (nr & 31));
	}
}

static __inline__ int __test_and_change_bit( int nr, volatile void* addr )
{
	int oldbit;
	if( (oldbit = constant_test_bit(nr, addr)) == 1){
		(((volatile unsigned int *) addr)[nr >> 5]) &= (0xFFFFFFFF ^ (1UL << (nr & 31)));
	}else{
		(((volatile unsigned int *) addr)[nr >> 5]) |= (1UL << (nr & 31));
	}
	return oldbit;
}

#define MARK_USED(index, order, area) __change_bit((index) >> (1+(order)), (area)->map)

void init_memory( void )
{
	int i;

	if( ( mem_size <= 0 ) || ( mem_size % PAGE_SIZE ) != 0 )
	{
		printf( "allocate size %d bytes, not permited \t \n", mem_size );
		_exit( -1 );
	}

	ready_for_memory();

	printf( "allocation memory, size %d bytes \t \n", mem_size );

	free_pages = TOTAL_PAGES(mem_size);
	printf( "total number of page : %ld\n", free_pages );

	printf( "make memory map..(page) \n" );

	mem_offset = sizeof( struct page ) * TOTAL_PAGES( mem_size );
	lmem_map = (struct page*)real_memory;

	//initialize struct free_area_t
	for( i = 0; i < max_order; i++ )
	{
		unsigned long bitmap_size;
		//make list head for free list
		INIT_LIST_HEAD( &free_area[i].free_list );
		
		bitmap_size = ( mem_size - 1 ) >> ( i + 4 );
		bitmap_size = LONG_ALIGN( bitmap_size + 1 );

		//get bitmap address in real_memory
		free_area[i].map = (unsigned long*)get_address_map( bitmap_size );
		*(free_area[i].map) = 0;
	}

	//ready for page structure
	mem_offset = STRUCT_DATA;
	mapping_page( lmem_map );

	init_buddy();

}

int cal_cur_order( unsigned long mem ) 
{
	int i = BUDDY_MAX_ORDER - 1;

	while( i >= 0 )
	{
		if( (mem) == ( PAGE_SIZE << i ) )
		{
			return i;
		}
		i--;
	}
	if( mem > ( PAGE_SIZE << (BUDDY_MAX_ORDER - 1 )))
			return (BUDDY_MAX_ORDER);

	return (int)NULL;
}

void init_buddy( void )
{
	unsigned long nr_next, nr_prev;
	int cur_order = BUDDY_MAX_ORDER - 1;

	unsigned long total_page = free_pages;
	unsigned long top_buddy_size = PAGE_SIZE << cur_order;
	free_area_t *area = &free_area[cur_order];

	if( (top_buddy_size * 2) >= ( mem_size ))
	{
		cur_order = cal_cur_order( mem_size );
		area = &free_area[--cur_order];
	}

	printf("cur_order: %d\n", cur_order);

	top_buddy_size = PAGE_SIZE << cur_order;
	unsigned long order_page = TOTAL_PAGES( top_buddy_size );

	//first list entry free_list to page
	list_add( &(lmem_map[0]).list, &(area)->free_list );
	
	nr_prev = 0;
	nr_next = 0;

	// page to page in free_area list 
	while( 1 )
	{
		nr_prev = nr_next;
		nr_next = nr_prev + ( 1UL << cur_order ); 

		if( nr_next + order_page >= total_page )
		{
			list_add( &(lmem_map[nr_next]).list, &(area)->free_list );
			MARK_USED( nr_prev,cur_order, area);
			break;
		}

		while( ( total_page - nr_next ) <= order_page )
		{
			if( cur_order == 0 )
				break;

			cur_order--;
			area--;
			
			order_page = 1 << cur_order;
		}

		nr_prev = nr_next;
		list_add( &(lmem_map[nr_prev]).list, &(area)->free_list );
		MARK_USED( nr_prev,cur_order, area);
	}
}

void free_memory( void )
{
	munmap( real_memory, mem_size );
	printf( "Free allocated real memory.. \n" );
}

int input_size( void )
{
	printf( "total memory size(KB)? " );
	scanf( "%d", &mem_size );

	mem_size *= 1024;
	return max_order = cal_cur_order( mem_size );
}

unsigned long __get_free_pages( unsigned int gfp_mask, unsigned int order )
{
	struct page *page;

	page = alloc_pages( gfp_mask, order );

	if( !page )
		return 0;

	return (unsigned long )page_address( page );
}

struct page* alloc_pages( unsigned int gfp_mask, unsigned int order )
{
	//NULL is zonelist_t *zonelist
	return __alloc_pages( gfp_mask, order, 	NULL ); 
}

struct page* __alloc_pages( unsigned int gfp_mask, unsigned int order, zonelist_t *zonelist )
{
	struct page* page;
	unsigned int curr_order = order;
	free_area_t *area = &free_area[order];

	struct list_head *head, *curr;

	do
	{
		head = &area->free_list;
		curr = head->next;
		
		if( curr != head )
		{
			unsigned long index;

			page = list_entry( curr, struct page, list );
			list_del( curr );
			index = GET_NR_PAGE( (unsigned long)page->addr );

			if( curr_order != max_order - 1 )
				MARK_USED( index, curr_order, area );

			free_pages -= 1UL << order;

			//give upper's page for allocation
			page = expand( NULL, page, index, order, curr_order, area );
			page->order = order;
			return page;
		}
		curr_order++;
		area++;

	} while( curr_order < max_order );

	return NULL;
}

struct page* expand( zone_t *zone, struct page *page, unsigned long index, int low, int high, free_area_t *area )
{
	unsigned long size = 1 << (high);

	while( high > low )
	{
		area--;
		high--;
		size >>= 1;
		list_add( &(page)->list, &(area)->free_list );
		MARK_USED( index, high, area );
		index += size;
		page += size;
	}

	return page;
}

//page deallocation
void _free_pages( void *ptr )
{
	int i;
	i = (((char *)ptr - (char *)lmem_map[0].addr ) >> PAGE_SHIFT );
	__free_pages( &lmem_map[i], lmem_map[i].order );
}

void __free_pages( struct page* page, unsigned int order )
{
	//if page checking
	__free_pages_ok( page, order );
}

void __free_pages_ok( struct page* page, unsigned int order )
{
	unsigned long index, page_idx, mask;
	free_area_t *area;

	mask = (~0UL) << order;
	page_idx = GET_NR_PAGE( (unsigned long)page->addr );

	//need page align confim
	index = page_idx >> ( 1 + order );

	area = &free_area[order];
	free_pages -= mask;

	while( mask + (1 << (max_order-1)))
	{
		struct page *buddy1, *buddy2;

		if( area >= free_area + max_order )
		{
			printf( "over free_area boundary \n" );
			break;
		}
		
		if( !__test_and_change_bit( index, area->map ) ){
			break; //buddy page is still allocated.
		}

		buddy1 = &lmem_map[( (page_idx) ^ -mask )];
		buddy2 = &lmem_map[page_idx];

		list_del( &buddy1->list );
		mask <<= 1;
		area++;
		index >>= 1;
		page_idx &= mask;
	}

	list_add( &lmem_map[page_idx].list, &area->free_list );
}

void _show_free_order_list( int order )
{
	free_area_t *area = &free_area[order];
	struct page *p, *q;

	p = (struct page*)(area)->free_list.next;
	q = (struct page*)&(area)->free_list;
	printf( "--------------order %d---------------\n", order );

	while( p != q )
	{
		printf( "%ld \t", GET_NR_PAGE((unsigned long)p->addr) );
		p = (struct page*)p->list.next;
	}
	printf("\t"); show_bitmap(*area->map);
	printf( "\n-------------------------------------\n" );
}
