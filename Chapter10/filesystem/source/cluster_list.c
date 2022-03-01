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
	clist->head = NULL;

	return 0;
}

int cluster_list_push(struct cluster_list *clist, sector_t cluster)
{
	struct cluster_list_element *entry;

	if (clist == NULL)
		return -1;

	if (clist->push_offset == CLUSTER_LIST_CLUSTER_PER_ELEMENT 
	||  clist->head == NULL)
	{
		entry = (struct cluster_list_element *) malloc (
			sizeof(struct cluster_list_element)
		);

		if (entry == NULL)
			return -1;

		list_init(&entry->list);

		if (clist->head == NULL) {
			clist->tail = clist->head = &entry->list;
		} else {
			list_add(clist->tail, &entry->list);
			clist->tail = &entry->list;
		}

		clist->push_offset = 0;
	}

	entry = LIST_ENTRY(
		clist->tail,
		struct cluster_list_element,
		list
	);

	entry->clusters[clist->push_offset++] = cluster;
	clist->count++;

	return 0;
}

int cluster_list_pop(struct cluster_list *clist, sector_t *cluster)
{
	struct cluster_list_element *entry;

	if (clist == NULL || clist->count == 0)
		return -1;

	entry = LIST_ENTRY(
		clist->head,
		struct cluster_list_element,
		list
	);

	*cluster = entry->clusters[clist->pop_offset++];
	clist->count--;
	
	if (clist->pop_offset == CLUSTER_LIST_CLUSTER_PER_ELEMENT) {	
		list_del(&entry->list);
		if (clist->head == clist->tail)
			clist->tail = clist->head = NULL;
		else
			clist->head = clist->head->next;

		clist->pop_offset = 0;
		free(entry);
	}	

	return 0;
}

void cluster_list_release(struct cluster_list *clist)
{
	if (clist == NULL)
		return ;

	LIST_ITERATOR_WITH_ENTRY(clist->head, entry,
			         struct cluster_list_element, list)
		free(entry);
	LIST_ITERATOR_END

	clist->head = NULL;
	clist->count = 0;
}
