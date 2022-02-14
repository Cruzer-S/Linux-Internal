#ifndef LIST_H__
#define LIST_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "exstdlib.h"

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(HEAD) { .next = &(HEAD), .prev = &(HEAD) }

#define LIST_ENTRY container_of

#define LIST_ITERATOR_WITH_ENTRY(HEAD, ENTRY, TYPE, MEMBER)			\
	do {	if (HEAD == NULL)						\
			break;							\
										\
		struct list_head *__LIST_START = HEAD,				\
		                 *__LIST_END   = HEAD;				\
		do {								\
			TYPE *ENTRY = container_of(__LIST_START, TYPE, MEMBER);
			/*
			 * ...
			 */
#define LIST_ITERATOR_END							\
		} while ( __LIST_START = __LIST_START->next,			\
			  __LIST_START != __LIST_END         ) ;		\
	} while (false);

#define LIST_ITERATOR_DELETE_ENTRY	list_del(__LIST_START)
#define LIST_ITERATOR_BREAK		break
#define LIST_ITERATOR_CONTINUE		continue

void list_init(struct list_head *head);

void list_add(struct list_head *head, struct list_head *new);
void list_del(struct list_head *head);

void list_add_tail(struct list_head *, struct list_head *);

#endif
