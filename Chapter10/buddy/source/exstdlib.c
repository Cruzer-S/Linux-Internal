#include "exstdlib.h"

#include <stdio.h>	// for printf() series
#include <stdlib.h>	// for malloc()
#include <stdarg.h>	// for va_*** series

int cprintf(const char *fmt, char chr, int width, ...)
{
	char *fmtstr, *alignstr, *trackstr;
	int fmtlen, padlen, rem;
	va_list ap;

	va_start(ap, width);
		fmtlen = vsnprintf(NULL, 0, fmt, ap);
		fmtstr = malloc(fmtlen + 1);
		if(fmtstr == NULL)
			goto RETURN_ERR;

		vsprintf(fmtstr, fmt, ap);
	va_end(ap);

	padlen = (fmtlen >= width) ? 0 : width - fmtlen;
	rem    = padlen % 2;

	alignstr = malloc(fmtlen + padlen + 1);
	if (alignstr == NULL)
		goto FREE_FMT_STR;

	trackstr = alignstr;
	memset_mv(trackstr, chr, padlen / 2);
	memcpy_mv(trackstr, fmtstr, fmtlen);
	memset_mv(trackstr, chr, padlen / 2 + rem);
	*trackstr = '\0';

	fputs(alignstr, stdout);

	free(fmtstr); free(alignstr);
	return fmtlen + padlen;

FREE_FMT_STR:	free(fmtstr);
RETURN_ERR:	return -1;
}
