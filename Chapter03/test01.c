#include <stdio.h>
#include <stdlib.h>

#define VALNAME(VAL) #VAL

int glob;

int main(void)
{
	int local, *dynamic;

	dynamic = malloc(1024);
	if (dynamic == NULL)
		exit(EXIT_FAILURE);

	printf("Local (%s) Address     : %10p\n", VALNAME(local), &local);
	printf("Dynamic (%s) Address : %10p\n", VALNAME(dynamic), dynamic);
	printf("Global (%s) Address     : %10p\n", VALNAME(glob), &glob);

	printf("main function Address     : %10p\n", main);

	return 0;
}
