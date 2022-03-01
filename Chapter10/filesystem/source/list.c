#include "list.h"

static void __list_add(
		struct list_head *, struct list_head *, struct list_head *
);

void list_init(struct list_head *head)
{
	head->next = head;
	head->prev = head;
}

void list_add(struct list_head *head, struct list_head *new)
{
	__list_add(head, new, head->next);
}

void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;

	entry->next = entry->prev = NULL;
}

void list_add_tail(struct list_head *head, struct list_head *new)
{
	__list_add(head->prev, new, head);
}

static void __list_add(struct list_head *prev, struct list_head *new, struct list_head *next)
{
	/*
	 * prev <-> new <-> next
	 */
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
