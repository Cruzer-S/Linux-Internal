#ifndef SHELL_ENTRY_H_
#define SHELL_ENTRY_H_

#include <stdint.h>
#include <stdbool.h>

struct shell_filetime {
	uint16_t year;
	uint8_t month;
	uint8_t day;

	uint8_t hour;
	uint8_t minute;
	uint8_t second;
} ;

struct shell_permition {
	uint8_t owner;
	uint8_t group;
	uint8_t other;
};

struct shell_entry {
	struct shell_entry *parent;

	char name[256];
	bool is_dir;
	unsigned int size;

	struct shell_permition permition;
	struct shell_filetime create_time,
			      modify_time;

	char pdata[1024];

	struct list_head *list;
};

struct shell_entry_list {
	unsigned int count;
	struct list_head *head, *tail;
};

int shell_entry_list_init(struct shell_entry_list *);
int shell_entry_list_add(struct shell_entry_list *, struct shell_entry *);
void shell_entry_list_release(struct shell_entry_list *);

#endif
