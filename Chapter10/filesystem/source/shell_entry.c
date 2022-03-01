#include "shell_entry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"

int shell_entry_list_init(struct shell_entry_list *list)
{
	list->head = list->tail = NULL;
	list->count = 0;

	return 0;
}

int shell_entry_list_add(
		struct shell_entry_list *list, struct shell_entry *entry
) {
	struct shell_entry *copy;

	copy = malloc(sizeof(struct shell_entry));
	if (copy == NULL)
		return -1;

	memcpy(copy, entry, sizeof(struct shell_entry));
	list_init(&copy->list);
	list->count++;

	if (list->head == NULL) {
		list->tail = list->head = &copy->list;
		return 0;
	}

	list_add(list->head, &copy->list);

	return 0;
}

void shell_entry_list_release(struct shell_entry_list *list)
{
	if (list->head == NULL)
		return ;

	if (list->head == list->tail) {
		list_del(list->head);
		return ;
	}

	for (struct list_head *first = list->head, *last = list->tail, *backup;
	     first != last;
	     first = backup)
	{
		backup = first->next;
		free(first);
		list_del(first);
	}

	list->head = list->tail = NULL;
	list->count = 0;
}
