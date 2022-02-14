#include <stdio.h>
#include <stdlib.h>

#include "buddy.h"
#include "bitmap.h"
#include "list.h"

#define BITMAP_SHOW(BITMAP) bitmap_show_all(BITMAP, true)

struct page_list {
	struct page *page;
	struct list_head head;
};

int free_page(struct buddy_allocator *buddy, struct list_head **main)
{
	int index, order, cnt = 0;

	if (main == NULL) goto RETURN_ERR;

	printf("index(1 ~ +) or order(- ~ 0): ");
	scanf("%d", &index);

	if (index <= 0) order = -index;
	else		order = -1;

	LIST_ITERATOR_WITH_ENTRY(*main, entry, struct page_list, head)
		if (++cnt == index || entry->page->order == order) {
			buddy_page_free(buddy, entry->page);

			if (&entry->head == *main) {
				if (entry->head.next == &entry->head)
					*main = NULL;
				else
					*main = entry->head.next;
			}

			LIST_ITERATOR_DELETE_ENTRY;

			free(entry);

			return 0;
		}
	LIST_ITERATOR_END

RETURN_ERR: return -1;
}

int alloc_page(struct buddy_allocator *buddy, struct list_head **main)
{
	struct page_list *new_plist;
	int order;

	printf("order: "); scanf("%d", &order);
	if (order < 0) goto RETURN_ERR;

	new_plist = malloc(sizeof(struct page_list));
	if ( !new_plist )
		goto RETURN_ERR;

	list_init(&new_plist->head);
	new_plist->page = buddy_page_alloc(buddy, order);
	if ( !new_plist->page )
		goto FREE_PLIST;

	if ( !*main )	*main = &new_plist->head;
	else		list_add((*main)->next, &new_plist->head);

	return 0;

FREE_PLIST:	free(new_plist);
RETURN_ERR:	return -1;
}

int show_page(struct list_head *main)
{
	int index = 0;

	if ( !main )
		return -1;

	LIST_ITERATOR_WITH_ENTRY(main, entry, struct page_list, head)
		printf("index: %d\t", ++index);
		printf("order: %d\n", entry->page->order);
	LIST_ITERATOR_END

	return 0;
}

int main(void)
{
	struct buddy_allocator *buddy;
	struct list_head *main_list = NULL;

	int memsize, menu;

	printf("total memory size(KiB)? ");
	scanf("%d", &memsize); memsize *= 1024;

	buddy = buddy_create(memsize);
	if ( !buddy )
		exit(EXIT_FAILURE);

	while (true) {
		printf("1. allocate, 2. free, "
		       "3. show alloc list, 4. show free list, "
		       "5. quit \n");
		printf("Choose menu: "); scanf("%d", &menu);
		switch (menu) {
		case 1:	if (alloc_page(buddy, &main_list) < 0)
				printf("failed to allocate page!\n");
			break;

		case 2: if (free_page(buddy, &main_list) < 0)
				printf("failed to free page!\n");
			break;

		case 3: if (show_page(main_list) < 0)
				printf("failed to show page!\n");
			break;

		case 4: buddy_show_status(buddy, BUDDY_SHOW_ALL);
			break;

		case 5:	goto WHILE_LOOP_BREAK;
			break;

		default: printf("invalid menu number\n");
			 break;
		}

		putchar('\n');
	} WHILE_LOOP_BREAK:

	buddy_destroy(buddy);

	return 0;
}
