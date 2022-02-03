#ifndef LIST_H__
#define LIST_H__

#include <stdbool.h>
#include <stddef.h>

struct list_head {
	struct list_head *next, *prev;
};

#define INIT_LIST_HEAD(PTR) do {						\
	(PTR)->next = (PTR); (PTR)->prev = (PTR);				\
} while (false);

#define LIST_ENTRY(PTR, TYPE, MEMBER)						\
	(void *) ((char *) PTR + offsetof(TYPE, MEMBER))

void list_add(struct list_head *head, struct list_head *new);
void list_del(struct list_head *head);

void list_add_tail(struct list_head *, struct list_head *);

#endif
