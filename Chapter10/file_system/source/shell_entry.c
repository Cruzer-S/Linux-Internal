#include "shell_entry.h"

#include <stdio.h>

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
	if (list->head == NULL) {
		list->tail = list->head = entry->list;
		return 0;
	}

	list_add(list->head, entry->list);

	return 0;
}

void shell_entry_list_release(struct shell_entry_list *list)
{
	LIST_ITERATOR_WITH_ENTRY(list->head, __, struct shell_entry, list)
		(void) __;
		LIST_ITERATOR_DELETE_ENTRY;
	LIST_ITERATOR_END

	list->head = list->tail = NULL;
}
