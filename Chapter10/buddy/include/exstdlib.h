#ifndef EX_STDLIB_H__
#define EX_STDLIB_H__

#include <string.h>	// for memset()

#define memset_mv(DEST, VALUE, SIZE) memset(DEST, VALUE, SIZE),			\
				     DEST = (char *) (DEST) + (SIZE)
#define memcpy_mv(DEST, VALUE, SIZE) memcpy(DEST, VALUE, SIZE),			\
				     DEST = (char *) (DEST) + (SIZE)

int cprintf(const char *fmt, char chr, int width, ...);

#endif
