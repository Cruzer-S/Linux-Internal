#include <stdbool.h>
#include <stdio.h>

#include <unistd.h>

#include "scheduler.h"

#define DECLARE_TEST_FUNC(NAME, START, END, INC, PREFIX)\
	void test_func_##NAME(void *context)		\
	{						\
		printf("Enter %s\n", __FUNCTION__);	\
							\
		for (int i = START; i < END; i += INC) {\
			printf(PREFIX "%5d\n", i);	\
			usleep(50000);			\
		}					\
							\
		printf("End of the %s\n", __FUNCTION__);\
	}					       /*
********************************************************/

DECLARE_TEST_FUNC(one, 0, 15, 1, "TASK 1: ")
DECLARE_TEST_FUNC(two, 500, 700, 10, "\t\tTASK 2: ")
DECLARE_TEST_FUNC(three, 1000, 1005, 1, "\t\t\t\tTASK 3: ")

int main(void)
{
	// 부모 태스크 생성
	thread_init();

	// 태스크 3 개 생성
	thread_create(test_func_one, NULL);
	thread_create(test_func_two, NULL);
	thread_create(test_func_three, NULL);

	// 부모 태스크 실행
	thread_wait();

	return 0;
}
