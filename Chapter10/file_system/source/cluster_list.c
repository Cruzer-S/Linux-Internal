#include "cluster_list.h"

#include <stdio.h>	// for NULL
#include <stdlib.h>	// for malloc(), free()
#include <string.h>	// for memset()

int cluster_list_init(struct cluster_list *clist)
{
	if (clist == NULL)
		return -1;

	clist->count = 0;
	clist->pop_offset = clist->push_offset = 0;
	clist->first = clist->last = 0;

	return 0;
}

int cluster_list_push(struct cluster_list *clist, sector cluster)
{
	struct cluster_list_element *entry;

	if (clist == NULL)
		return -1;

	if (clist->push_offset == CLUSTER_LIST_CLUSTER_PER_ELEMENT 
	||  clist->first == NULL)
	{
		entry  = (struct cluster_list_element *) malloc (
			sizeof(struct cluster_list_element)
		);

		if (entry == NULL)
			return -1;

		list_init(&entry->list);

		if (clist->first == NULL)
			clist->first = &entry->list;
		else
			clist->last->next = &entry->list;

		clist->last = &entry->list;
		clist->push_offset = 0;
	}

	entry = LIST_ENTRY(clist->last, struct cluster_list_element, list);
	entry->clusters[clist->push_offset++] = cluster;
	clist->count++;

	return 0;
}

int cluster_list_pop(struct cluster_list *clist, sector *cluster)
{
	struct cluster_list_element *entry;

	if (clist == NULL || clist->count == 0)
		return -1;

	entry = LIST_ENTRY(clist->first, struct cluster_list_element, list);
	if (entry == NULL)
		return -1;

	*cluster = entry->clusters[clist->pop_offset++];
	clist->count--;

	if (clist->pop_offset == CLUSTER_LIST_CLUSTER_PER_ELEMENT) {
		struct list_head *next = entry->list.next;
		free(clist->first);

		clist->first = next;
		clist->pop_offset = 0;
	}

	return 0;
}

void cluster_list_release(struct cluster_list *clist)
{
	if (clist == NULL)
		return ;

	LIST_ITERATOR_WITH_ENTRY(clist->first, entry,
			         struct cluster_list_element, list)
		free(entry);
	LIST_ITERATOR_END

	clist->first = clist->last = NULL;
	clist->count = 0;
}
