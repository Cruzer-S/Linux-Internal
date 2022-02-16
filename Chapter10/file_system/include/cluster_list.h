#ifndef CLUSTER_LIST_H__
#define CLUSTER_LIST_H__

#include <stdint.h>

#include "list.h"

typedef uint32_t sector;

#define CLUSTER_LIST_CLUSTER_PER_ELEMENT	1023

struct cluster_list_element {
	sector clusters[CLUSTER_LIST_CLUSTER_PER_ELEMENT];

	struct list_head list;
};

struct cluster_list {
	uint32_t	count;
	uint32_t	push_offset;
	uint32_t	pop_offset;

	struct list_head *first, *last;
};

int cluster_list_init(struct cluster_list *);
int cluster_list_push(struct cluster_list *, sector );
int cluster_list_pop(struct cluster_list *, sector *);
void cluster_list_release(struct cluster_list *);

#endif
