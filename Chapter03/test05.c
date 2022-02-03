#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

int main(void)
{
	char *data;

	data = malloc(1024 * 1024 * 1024);
	if (data == NULL) {
		perror("failed to malloc(): ");
		exit(EXIT_FAILURE);
	}

	printf("Allocate memory\n");

	sleep(10);

	printf("Modifying data...\n");
	for (int i = 0; i < 1024 * 1024; i++)
		data[i * 1024] += 1;

	printf("all data is modified\n");

	sleep(10);

	return 0;
}
