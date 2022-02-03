#include <stdio.h>
#include <stdlib.h>

#include <sys/wait.h>
#include <unistd.h>

#include <linux/unistd.h>

int main(void)
{
	int pid, ret;

	switch (pid = fork()) {
	case -1:perror("failed to fork(): ");
		exit(EXIT_FAILURE);
	case 0:	printf("[Child] TGID: %d, PID: %ld\n",
			getpid(), syscall(__NR_gettid));
		break;
	default:printf("[Parent] TGID: %d, PID: %ld\n",
			getpid(), syscall(__NR_gettid));
		if (waitpid(pid, &ret, 0) == -1) {
			perror("failed to waitpid(): ");
			exit(EXIT_FAILURE);
		} else printf("return from the child: %d\n", ret);
		break;
	}

	return 0;
}
