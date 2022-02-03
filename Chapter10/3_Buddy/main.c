/********************************************************/
/*                                                      */
/* Project      : Buddy System                          */
/* File         : main.c                                */
/* Author       : Youn DaeSeok(woodsmano@gmail.com)     */
/* Company      : Dankook Univ. Embedded system lab.    */
/* Note         : buddy 테스트를 위한 main함수 		*/
/* Date         : 2008.7.3                              */
/*                                                      */
/********************************************************/

#include "Header/buddy.h"

int main( void )
{
	int order = input_size() - 1;

	int i = 0;
	struct page* page1;	
	struct page* page2;	
	struct page* page3;	
	
	init_memory();

	printf("Initial State\n");
	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf( "\n\n" );

	printf("Order1 page allocation\n");
	page1 = alloc_pages(0, 2);
	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf( "\n\n" );

	printf("Order2 page allocation\n");
	page2 = alloc_pages(0, 0);
	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf( "\n\n" );
	
	printf("Order3 page allocation\n");
	page3 = alloc_pages(0, 1);
	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf("Order1 page free\n");
	_free_pages( page1->addr );

	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf("Order3 page free\n");
	_free_pages( page3->addr );

	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	printf("Order2 page free\n");
	_free_pages( page2->addr );

	printf("free all allocation\n");

	for( i = 0; i <= order; i++ )
		_show_free_order_list( i );

	free_memory();

	return 0;
}
