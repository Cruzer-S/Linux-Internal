#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "scheduler.h"

// task switching 시 저장되어야 하는 정보
struct frame {
	// 플래그 레지스터, ARM 의 CPSR
	unsigned long flags;

	// Base stack pointer register
	unsigned long rbp;

	// Source and destination index register
	unsigned long rdi;
	unsigned long rsi;

	// 범용 레지스터(r[a~d]x)
	unsigned long rdx;
	unsigned long rcx;
	unsigned long rbx;
	unsigned long rax;

	// 콜백함수 등록
	unsigned long callback;
	unsigned long retaddr;
	unsigned long data;
};

// 현재 실행 중인 태스크를 관리하는 스케줄링 핸들러
struct sched_handler {
	int child_task;

	struct task_info *running_task;
	struct task_info *root_task;
} sched_handler;

struct task_info *task_get_running_task(void);
void task_insert(struct task_info *);
void task_delete(struct task_info *);
void task_next(void);
void scheduler(void);
void parent_task(void *);

// 새로운 태스크 생성
struct task_info *thread_create(task_func callback, void *context)
{
	struct task_info *task;
	struct frame *frame;

	task = malloc(sizeof(struct task_info));
	if (task == NULL)
		return NULL;

	memset(task, 0x00, sizeof(struct task_info));

	// 동적할당한 태스크의 스택 최하단을 (메모리 기준으론 최상단)
	// 태스크의 상태 정보 저장을 위한 공간으로 사용
	frame = (struct frame *) &(task->stack[
		THREAD_STACKSIZE - sizeof(struct frame)
	]);

	// 오버플로우 체크
	for (int i = 0; i < THREAD_STACKSIZE; i++)
		task->stack[i] = i;

	// 스택 프레임 초기화
	memset(frame, 0x00, sizeof(struct frame));
	frame->callback = (unsigned long) callback;
	frame->retaddr = (unsigned long) thread_kill;
	frame->data = (unsigned long) context;
	// rbp 에는 rax 멤버 변수의 주소를 저장, 그래야 callback 이 호출됨.
	// GDB 로 Assembly 코드를 보면 쉽게 이해 가능
	frame->rbp = (unsigned long) &frame->rax;

	task->sp = (unsigned long) frame;

	sched_handler.child_task++;
	task->task_id = sched_handler.child_task;
	task->status = TASK_STATUS_READY;

	task_insert(task);

	return task;
}

// 부모 태스크 생성
void thread_init(void)
{
	sched_handler.root_task = NULL;
	sched_handler.running_task = NULL;

	sched_handler.child_task = 0;

	thread_create(parent_task, NULL);
}

// 쓰레드 전환
static unsigned long spsave, sptmp;
void thread_switch(int unused)
{
	// 레지스터의 정보를 백업한다.
	asm(	"push %%rax	\n\t"
		"push %%rbx	\n\t"
		"push %%rcx	\n\t"
		"push %%rdx	\n\t"
		"push %%rsi	\n\t"
		"push %%rdi	\n\t"
		"push %%rbp	\n\t"
		"pushf		\n\t"
		"mov %%rsp, %0	": "=r" (spsave));

	// 실행 중인 태스크의 sp 를 저장
	sched_handler.running_task->sp = spsave;

	// running_task 를 다음에 실행될 태스크로 전환
	scheduler();

	// 다음 태스크의 stack pointer 를 sptmp 에 저장
	sptmp = sched_handler.running_task->sp;

	// 레지스터의 값을 실행될 태스크의 이전 정보로 복원
	asm(	"mov %0, %%rsp	\n\t"
		"popf		\n\t"
		"pop %%rbp	\n\t"
		"pop %%rdi	\n\t"
		"pop %%rsi	\n\t"
		"pop %%rdx	\n\t"
		"pop %%rcx	\n\t"
		"pop %%rbx	\n\t"
		"pop %%rax	\n\t"
		::"r" (sptmp));
}

// 다음에 실행될 태스크를 선택
void scheduler(void)
{
	struct task_info *task;

	task = task_get_running_task();
	switch (task->status) {
	case TASK_STATUS_RUN:
	case TASK_STATUS_SLEEP:
		break;

	case TASK_STATUS_KILL:
		task_delete(task);
		scheduler();
		break;

	case TASK_STATUS_YIELD:
		task->status = TASK_STATUS_RUN;
		break;

	case TASK_STATUS_READY:
		task->status = TASK_STATUS_RUN;
		break;
	}

	task_next();
}

// 쓰레드 대기, thread_join()
void thread_wait(void)
{
	parent_task(NULL);
}

// 현재 실행 중인 쓰레드를 죽임
void thread_kill(void)
{
	struct task_info *task;

	task = task_get_running_task();
	task->status = TASK_STATUS_KILL;

	thread_switch(0);
}

// empty function
void thread_uninit(void)
{
	return /* null statement */;
}

// 메인 태스크 실행.
void parent_task(void *context)
{
	struct sigaction act;
	sigset_t masksets;
	pid_t pid;

	sigemptyset(&masksets);
	act.sa_handler = thread_switch;
	act.sa_mask = masksets;
	act.sa_flags = SA_NODEFER;

	sigaction(SIGUSR1, &act, NULL);

	if ((pid = fork()) == 0) {
		// 자식 프로세스, 자식 프로세스는 부모 프로세스에게
		// 주기적으로 시그널을 던져서 등록된 signal handler 함수가
		// 호출될 수 있게 한다. (이 함수가 바로 thread_switch)
		// usleep 의 값을 늘이고 줄임으로 문맥 전환 시간을
		// 변경할 수 있다.
		while (true) {
			usleep(200000);
			kill(getppid(), SIGUSR1);
		}
	} else while (true) {
		// 부모 프로세스, 부모 프로세스는 태스크의 수가
		// 1 이 될 때까지 (본인만 남을 때까지) 대기한다.
		if (sched_handler.child_task == 1) {
			// 꾸준히 시그널을 날려주던 자식 태스크를 종료
			kill(pid, SIGINT);
			wait(NULL);
			break;
		}
	}
}

// 새로운 태스크 삽입
void task_insert(struct task_info *task)
{
	if (sched_handler.root_task == NULL) {
		sched_handler.root_task = task;
		sched_handler.running_task = task;
	} else {
		struct task_info *temp;

		temp = sched_handler.root_task;
		while (temp->next != NULL)
			temp = temp->next;

		temp->next = task;
		task->prev = temp;
	}
}

// 현재 실행 중인 태스크를 반환하는 함수
struct task_info *task_get_running_task(void)
{
	return sched_handler.running_task;
}

// 연결 리스트를 통해 현재 실행 중인 태스크를 다음으로 옮김
void task_next(void)
{
	struct task_info *temp;

	temp = sched_handler.running_task;
	if (temp->next != NULL)
		sched_handler.running_task = temp->next;
	else
		sched_handler.running_task = sched_handler.root_task;
}

// 인자로 전달된 태스크 구조체 할당 해제
void task_delete(struct task_info *task)
{
	struct task_info *temp = task->prev;

	printf("delete task %d\n", task->task_id - 1);

	if (sched_handler.root_task == task) {
		sched_handler.root_task = NULL;
		sched_handler.running_task = NULL;
		sched_handler.child_task = 0;
	} else {
		temp->next = task->next;

		if (task == sched_handler.running_task) {
			if (temp->next != NULL) {
				(task->next)->prev = temp;
				sched_handler.running_task = temp->next;
			} else {
				sched_handler.running_task = temp;
			}
		}

		sched_handler.child_task--;
	}

	free(task);
}
