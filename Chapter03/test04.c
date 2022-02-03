#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	pid_t pid;
	int exit_status;

	switch (pid = fork()) {
	case -1:perror("failed to fork(): ");
		exit(EXIT_FAILURE);
		break;

	case 0:	printf("before exec\n");
		execl("./fork", "fork", NULL);
		printf("After exec\n");
		break;

	default:pid = wait(&exit_status);
		break;
	}

	printf("parent \n");

	return 0;
}
