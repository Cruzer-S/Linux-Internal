/********************************************************/
/*                                                      */
/* Project      : Buddy System                          */
/* File         : list.h                                */
/* Author       : Youn DaeSeok(woodsmano@gmail.com)     */
/* Company      : Dankook Univ. Embedded system lab.    */
/* Note         : ���� ���� ����Ʈ�� ���� �Լ� ���� ��  */ 
/* 				  �ڷᱸ�� 		*/
/* Date         : 2008.7.3                              */
/*                                                      */
/********************************************************/

struct list_head
{
	struct list_head *next, *prev;
};

#define INIT_LIST_HEAD(ptr) \
	(ptr)->next = (ptr); (ptr)->prev = (ptr);

#define list_entry( ptr, type, member ) \
	((type*)((char*)(ptr)-(unsigned long)(&((type *)0)->member)))

void list_add( struct list_head*, struct list_head *);
void __list_add( struct list_head *, struct list_head*, struct list_head* );
void list_del( struct list_head * );
void __list_del( struct list_head *, struct list_head * );
void list_add_tail( struct list_head*, struct list_head *);
