#include "bitmap.h"

#include <stdio.h>	// fputc()
#include <stdlib.h>	// malloc(), free()
#include <limits.h>	// CHAR_BIT
#include <string.h>	// memset()

typedef char byte;

#define TYPE_ALIGN(TYPE, X)		( ((X) + ((TYPE) - 1)) / (TYPE) )

#define BITMAP_SIZE			(sizeof(btype) * CHAR_BIT)
#define BITS_TO_BYTE(BITS)		TYPE_ALIGN(CHAR_BIT, BITS)
#define BITMAP_INDEX_ALIGN(BITSIZE)	TYPE_ALIGN(				\
						sizeof(btype),			\
						BITS_TO_BYTE(BITSIZE)		\
					)
#define BITMAP_INDEX(BITSIZE)		((BITSIZE) / (CHAR_BIT * sizeof(btype)))
#define BYTE_BIT			CHAR_BIT

#define COMP(X, Y)			(((X) > (Y)) ? 1 : -1)

enum bitmap_alloc {
	BITMAP_ALLOC_BY_MALLOC,
	BITMAP_ALLOC_ADDR_ONLY,
	BITMAP_ALLOC_FULL_STRUCT
};

typedef unsigned int btype;

struct bitmap {
	int size;
	btype *map;

	enum bitmap_alloc type;
};

// static void __bitmap_show(btype *map, int index, int shift, bool high_first);

Bitmap __bitmap_create(uint64_t size, void *addr, int addr_size)
{
	Bitmap bitmap = NULL;
	btype *map_addr = NULL;
	enum bitmap_alloc type;

	if (addr != NULL) {
		int addr_only = BITS_TO_BYTE(size);
		int full_struct = addr_only + sizeof(struct bitmap);

		if (addr_size >= full_struct)
			type = BITMAP_ALLOC_FULL_STRUCT;
		else if (addr_size >= addr_only)
			type = BITMAP_ALLOC_ADDR_ONLY;
		else
			return NULL;
	} else type = BITMAP_ALLOC_BY_MALLOC;

	switch (type) {
	case BITMAP_ALLOC_FULL_STRUCT:
		bitmap = addr;
		addr = (byte *) addr + sizeof(struct bitmap);

	case BITMAP_ALLOC_ADDR_ONLY:
		map_addr = addr;

	case BITMAP_ALLOC_BY_MALLOC:
		if (bitmap == NULL) {
			bitmap = malloc(sizeof(struct bitmap));

			if (bitmap == NULL)
				return NULL;
		}

		if (map_addr == NULL) {
			map_addr = malloc(
				BITMAP_INDEX_ALIGN(size) * sizeof(btype)
			);

			if (map_addr == NULL) {
				if (type == BITMAP_ALLOC_BY_MALLOC)
					free(bitmap);

				return NULL;
			}
		}
	}

	bitmap->map = map_addr;
	bitmap->type = type;
	bitmap->size = BITMAP_INDEX_ALIGN(size);

	return bitmap;
}

Bitmap bitmap_create(uint64_t size)
{
	return __bitmap_create(size, NULL, 0);
}

int __bitmap_calc_alloc_size(bool is_full_struct, uint64_t size)
{
	int addr_only = BITS_TO_BYTE(size);
	int full_struct = addr_only + sizeof(struct bitmap);

	return (is_full_struct ? full_struct : addr_only);
}

void bitmap_clear(Bitmap bitmap)
{
	memset(bitmap->map, 0x00, bitmap->size * sizeof(btype));
}

bool bitmap_get(Bitmap bitmap, uint64_t pos)
{
	int idx = BITMAP_INDEX(pos);

	return	(bitmap->map[idx])
	      & (((btype) 1) << (pos & (BITMAP_SIZE - 1)));
}

bool bitmap_switch(Bitmap bitmap, uint64_t pos)
{
	bool prev = bitmap_get(bitmap, pos);

	bitmap_set(bitmap, pos, !prev);

	return prev;
}

void bitmap_set(Bitmap bitmap, uint64_t pos, bool set)
{
	int idx = BITMAP_INDEX(pos);
	int shift = pos % BITMAP_SIZE;

	if (set)
		bitmap->map[idx] |= ((btype) 1) << shift;
	else
		bitmap->map[idx] &= ((~((btype) 0)) ^ (((btype) 1) << shift));
}

uint64_t bitmap_size(Bitmap bitmap)
{
	return (bitmap->size * BITMAP_SIZE);
}

void bitmap_show_all(Bitmap bitmap, bool high_start)
{
	uint64_t start, end;

	if (high_start)	start = bitmap_size(bitmap) - 1, end = 0;
	else		start = 0, end = bitmap_size(bitmap) - 1;

	bitmap_show_area(bitmap, start, end);
}

void bitmap_show_area(Bitmap bitmap, uint64_t start, uint64_t end)
{
	int nr;

	for (nr = start; nr != end; nr += COMP(end, start)) {
		fputc(bitmap_get(bitmap, nr) ? '1' : '0', stdout);
		if (nr != 0) {
			if (nr % BYTE_BIT == 0)
				fputc(' ', stdout);

			if (nr % BITMAP_SIZE == 0)
				fputc('\t', stdout);
		}
	}

	fputc(bitmap_get(bitmap, nr) ? '1' : '0', stdout);
}

void bitmap_destroy(Bitmap bitmap)
{
	switch (bitmap->type) {
	case BITMAP_ALLOC_BY_MALLOC:
		free(bitmap->map);

	case BITMAP_ALLOC_ADDR_ONLY:
		free(bitmap);

	case BITMAP_ALLOC_FULL_STRUCT:
		/* do nothing */ ;
	}
}
