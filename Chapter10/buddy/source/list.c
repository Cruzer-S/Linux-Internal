#include "list.h"

void list_add(struct list_head *head, struct list_head *new)
{
	// link with (new) <=> (head->next)
	head->next->prev = new;
	new->next = head->next;

	// link with (head) <=> (new)
	new->prev = head;
	head->next = new;
}

void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;

	entry->next = entry->prev = NULL;
}

void list_add_tail(struct list_head *head, struct list_head *new)
{
	head->prev->next = new;
	new->prev = head->prev;

	head->prev = new;
	new->next = head;
}
