#ifndef EX_STDLIB_H__
#define EX_STDLIB_H__

#include <string.h>	// for memset()
#include <stdbool.h>	// for bool type
#include <stdint.h>

#define memset_mv(DEST, VALUE, SIZE) memset(DEST, VALUE, SIZE),			\
				     DEST = (char *) (DEST) + (SIZE)
#define memcpy_mv(DEST, VALUE, SIZE) memcpy(DEST, VALUE, SIZE),			\
				     DEST = (char *) (DEST) + (SIZE)

#define container_of(PTR, TYPE, MEMBER)						\
		((TYPE *) ((char *) (PTR) - offsetof(TYPE, MEMBER)))

#define NEWLINE	 putchar('\n')

#define PTR_ADD(PTR, VALUE) *((intptr_t *) &(PTR)) += VALUE

int cprintf(const char *fmt, char chr, int width, ...);

#endif
