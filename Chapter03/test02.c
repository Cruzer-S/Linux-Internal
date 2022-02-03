#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int g = 2;

int main(void)
{
	pid_t pid;
	int l = 3;
	int ret;

	printf("PID(%d): Parent g = %d, l = %d\n",
		getpid(), g, l);

	switch (pid = fork()) {
	case -1:perror("failed to fork(): ");
		exit(EXIT_FAILURE);

	case 0:	g++; l++;
		break;

	default:if (wait(&ret) == -1)
			perror("failed to wait(): ");
		break;
	}

	printf("PID(%d): g = %d, l = %d\n",
		getpid(), g, l);

	return 0;
}
