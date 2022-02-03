#include <stdio.h>
#include <stdlib.h>

#include "buddy.h"
#include "bitmap.h"

#define SHOW_FREE_ORDER_LIST(MSG, ...) do {					\
	printf(MSG, __VA_ARGS__);						\
	for (int i = 0; i < 10; i++)						\
		buddy_show_free_list(buddy, i);					\
	fputs("\n\n", stdout);							\
} while (false)

#define BITMAP_SHOW(BITMAP) bitmap_show_all(BITMAP, true)

void test_bitmap(void)
{
	struct bitmap *bitmap;

	bitmap = bitmap_create(72);
	if (bitmap == NULL) {
		printf("failed to create bitmap\n");
		exit(EXIT_FAILURE);
	}

	printf("clear bitmap\n");
	bitmap_clear(bitmap);
	BITMAP_SHOW(bitmap); fputc('\n', stdout);

	printf("set 32 bit\n");
	bitmap_set(bitmap, 32, true);
	BITMAP_SHOW(bitmap); fputc('\n', stdout);

	printf("set 60 ~ 70 bit\n");
	for (int i = 60; i <= 70; i++)
		bitmap_set(bitmap, i, true);
	BITMAP_SHOW(bitmap); fputc('\n', stdout);

	printf("switch 50, 55, 65, 70 bit\n");
	printf("previous bit: ");
	for (int i = 50; i <= 70; i += 5)
		printf("%d => %d\t", i, bitmap_switch(bitmap, i));
	printf("\n");

	BITMAP_SHOW(bitmap); fputc('\n', stdout);

	printf("clear bitmap\n");
	bitmap_clear(bitmap);
	BITMAP_SHOW(bitmap); fputc('\n', stdout);

	bitmap_destroy(bitmap);
}

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
	SHOW_FREE_ORDER_LIST("%s", "initial state\n");

	// ---------------------------------------------------------------------
	// Allocate memory
	// ---------------------------------------------------------------------
	for (int i = 0; i < 4; i++) {
		page[i] = buddy_page_alloc(buddy, 0, i);
		SHOW_FREE_ORDER_LIST("allocate %s page(s)\n", square_str[i]);
	}

	// ---------------------------------------------------------------------
	// Free memory
	// ---------------------------------------------------------------------
	for (int i = 0; i < 4; i++) {
		buddy_page_free(buddy, page[i]);
		SHOW_FREE_ORDER_LIST("free %s page(s)\n", square_str[i]);
	}

	buddy_destroy(buddy);

	return 0;
}
