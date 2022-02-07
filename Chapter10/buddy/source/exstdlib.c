#include "exstdlib.h"

#include <stdio.h>	// for printf() series
#include <stdlib.h>	// for malloc()
#include <stdarg.h>	// for va_*** series
#include <stdbool.h>	// true, false

int cprintf(const char *fmt, char chr, int width, ...)
{
	static bool rem_dir = true;
	char *fmtstr, *alignstr, *trackstr;
	int fmtlen, padlen, rem;
	va_list ap_for_len, ap_for_read;

	if (fmt == NULL)
		return (rem_dir = !rem_dir);

	va_start(ap_for_len, width);
		va_copy(ap_for_read, ap_for_len);
		fmtlen = vsnprintf(NULL, 0, fmt, ap_for_len);
		fmtstr = malloc(fmtlen + 1);
		if(fmtstr == NULL)
			goto RETURN_ERR;

		vsprintf(fmtstr, fmt, ap_for_read);
		va_end(ap_for_read);
	va_end(ap_for_len);

	padlen = (fmtlen >= width) ? 0 : width - fmtlen;
	rem    = padlen % 2;

	alignstr = malloc(fmtlen + padlen + 1);
	if (alignstr == NULL)
		goto FREE_FMT_STR;

	trackstr = alignstr;
	memset_mv(trackstr, chr, padlen / 2 + (rem * (rem_dir == true)));
	memcpy_mv(trackstr, fmtstr, fmtlen);
	memset_mv(trackstr, chr, padlen / 2 + (rem * (rem_dir == false)));
	*trackstr = '\0';

	fputs(alignstr, stdout);

	free(fmtstr); free(alignstr);
	return fmtlen + padlen;

FREE_FMT_STR:	free(fmtstr);
RETURN_ERR:	return -1;
}
