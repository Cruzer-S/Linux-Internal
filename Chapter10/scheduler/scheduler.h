#ifndef SCHEDULER_H__
#define SCHEDULER_H__

#define THREAD_STACKSIZE 1024

// 태스크 상태를 정의하는 열거형
enum task_status {
	TASK_STATUS_READY = 0,
	TASK_STATUS_RUN,
	TASK_STATUS_YIELD,
	TASK_STATUS_SLEEP,
	TASK_STATUS_KILL
};

/* [태스크 상태 구조체]
 *
 * $ 스택 메모리, 스택 포인터
 * $ 태스크 아이디, 태스크 상태
 * $ 이전 태스크, 다음 태스크 구조체 포인터
 */
struct task_info {
	unsigned long stack[THREAD_STACKSIZE];
	unsigned long sp;

	int task_id;
	enum task_status status;

	struct task_info *prev;
	struct task_info *next;
};

// 태스크 생성에 사용되는 callback 함수 원형 정의
typedef void (*task_func)(void *context);

// 쓰레드를 생성하는 thread_create 함수 정의
struct task_info *thread_create(task_func callback, void *context);

// etc.
void thread_init(void);
void thread_wait(void);
void thread_uninit(void);
void thread_switch(int);
void thread_kill(void);

#endif
