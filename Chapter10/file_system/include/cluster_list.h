#ifndef CLUSTER_LIST_H__
#define CLUSTER_LIST_H__

#include <stdint.h>

#include "list.h"

typedef uint32_t sector_t;

#define CLUSTER_LIST_CLUSTER_PER_ELEMENT	1023

struct cluster_list_element {
	sector_t clusters[CLUSTER_LIST_CLUSTER_PER_ELEMENT];

	struct list_head list;
};

struct cluster_list {
	uint32_t	count;
	uint32_t	push_offset;
	uint32_t	pop_offset;

	struct list_head *first, *last;
};

int cluster_list_init(struct cluster_list *);
int cluster_list_push(struct cluster_list *, sector_t );
int cluster_list_pop(struct cluster_list *, sector_t *);
void cluster_list_release(struct cluster_list *);

#endif
