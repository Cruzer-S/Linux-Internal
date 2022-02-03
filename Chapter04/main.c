#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

char array[1024 * 1024 * 1024]; // 1 GiB

int main(void)
{
	srand((unsigned long) time(NULL));

	for (int i = 0; i < 1024 * 1024 * 1024; i++)
		array[i] = rand();

	while (true)
		/* do nothing */;

	return 0;
}
