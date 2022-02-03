#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sched.h>

#include <linux/unistd.h>

int func(void *arg)
{
	printf("[Chid] TGID: %d, PID: %ld\n",
		getpid(), syscall(__NR_gettid));

	sleep(2);

	return 0;
}

int main(void)
{
	int pid;

	int child_stack1[4096];
	int child_stack2[4096];

	printf("before clone\n");
	printf("[Parent] TGID: %d, PID: %ld\n",
		getpid(), syscall(__NR_gettid));

	clone(func, (void *) child_stack1 + 4095, 
	      CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID, NULL);

	clone(func, (void *) child_stack2 + 4096,
	      CLONE_VM | CLONE_THREAD | CLONE_SIGHAND, NULL);

	sleep(1);

	printf("after clone\n");

	return 0;
}
