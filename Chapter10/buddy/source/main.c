#include <stdio.h>
#include <stdlib.h>

#include "buddy.h"
#include "bitmap.h"

#define BITMAP_SHOW(BITMAP) bitmap_show_all(BITMAP, true)

int main(void)
{
	const char *square_str[] = { "one", "two", "four", "eight" };
	struct page *page[4];
	struct buddy_allocator *buddy;

	int memsize;

	printf("total memory size(KiB)? ");
	scanf("%d", &memsize); memsize *= 1024;

	buddy = buddy_create(memsize);
	if ( !buddy )
		exit(EXIT_FAILURE);

	// ---------------------------------------------------------------------
	// Initial state
	// ---------------------------------------------------------------------
	buddy_show_status(buddy);

	// ---------------------------------------------------------------------
	// Allocate memory
	// ---------------------------------------------------------------------
	for (int i = 0; i < 4; i++) {
		page[i] = buddy_page_alloc(buddy, 0, i);
		printf("allocate %s page(s)\n", square_str[i]);
		buddy_show_status(buddy); putchar('\n');
	}

	// ---------------------------------------------------------------------
	// Free memory
	// ---------------------------------------------------------------------
	for (int i = 0; i < 4; i++) {
		buddy_page_free(buddy, page[i]);
		printf("free %s page(s)\n", square_str[i]);
		buddy_show_status(buddy); putchar('\n');
	}

	buddy_destroy(buddy);

	return 0;
}
