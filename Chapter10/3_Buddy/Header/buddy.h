/********************************************************/
/*                                     		    	*/
/* Project      : Buddy System				*/
/* File		: buddy.h				*/
/* Author	: Youn DaeSeok(woodsmano@gmail.com)	*/
/* Company	: Dankook Univ. Embedded system lab.	*/
/* Note		: buddy system을 위한 설정 및 자료구조	*/
/* Date		: 2008.7.3				*/
/*                                     		    	*/
/********************************************************/


#ifndef _BUDDY_H_
#define _BUDDY_H_

#include "list.h"
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT) //page size 32 byte
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK) 
#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

#define BUDDY_MAX_ORDER	10
#define BUDDY_MAX_SIZE	(32*1024*1024)

#define TOTAL_MIN_SIZE	(32*1024*1024)
#define TOTAL_PAGES(size)	(size >> PAGE_SHIFT)

#define GET_NR_PAGE(addr)	((addr) - ((unsigned long)real_memory + mem_offset) ) >> (PAGE_SHIFT)
#define page_address( page ) ((page)->addr)

typedef struct free_area_struct
{
	struct list_head free_list;
	unsigned long *map;
} free_area_t;

typedef struct page
{
	struct list_head list;
	unsigned long flags;
	void *addr;
	int order;
} mem_map_t;

//struct zone : nothing to do now
typedef struct zonelist_struct
{
	int i;//zone member
}zonelist_t;

typedef struct zone_struct
{
	int j;
}zone_t;


void init_memory( void );
int input_size( void );
void free_memory( void );
void init_buddy( void );

int cal_cur_order( unsigned long );

//allocate bitmap
void alloc_bitmap( unsigned long*, unsigned long );
void ready_for_memory( void );
void* get_address_map( int );
void mapping_page( mem_map_t * );

#define ADDR	(*(volatile long*)addr)
unsigned long __get_free_pages( unsigned int, unsigned int );
struct page* alloc_pages( unsigned int, unsigned int );
struct page* __alloc_pages( unsigned int , unsigned int , zonelist_t * );

struct page* expand( zone_t *, struct page *, unsigned long , int , int , free_area_t *);

void _free_pages( void *ptr );
void __free_pages( struct page*, unsigned int );
void __free_pages_ok( struct page*, unsigned int );

void _show_free_order_list( int );
void _show_free_list_map( int );

#endif
