#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <pthread.h>

#include <linux/unistd.h>

void *func(void *data)
{
	int id;
	int i;
	pthread_t tid;

	id = *((int *) data);

	printf("[Child] TGID: %d, PID: %ld, pthread_self: %lu\n",
		getpid(), syscall(__NR_gettid), pthread_self());

	sleep(2);

	return (void *) 10 + id;
}

#define ERROR_HANDLING(STR, ...)	\
	fprintf(stderr, STR, ## __VA_ARGS__), exit(EXIT_FAILURE)

#define SIZE(X) (sizeof(X) / sizeof(*X))

int main(void)
{
	int pid, status;
	int a = 1;
	int b = 2;
	void *ret;

	pthread_t tid[2];

	printf("before pthread_create\n");

	if ((pid = pthread_create(&tid[0], NULL, func, (void *) &a)) != 0)
		ERROR_HANDLING("failed to pthread_create(): %s", strerror(pid));

	if ((pid = pthread_create(&tid[1], NULL, func, (void *) &b)) != 0)
		ERROR_HANDLING("failed to pthread_create(): %s", strerror(pid));

	for (int i = 0; i < SIZE(tid); i++) {
		pthread_join(tid[i], &ret);

		printf("pthread_join(): %p\n", ret);
	}

	printf("[Parent] TGID(%d), PID(%ld)\n",
		getpid(), syscall(__NR_gettid));

	return 0;
}
