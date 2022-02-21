#ifndef SHELL_H__
#define SHELL_H__

#include <stdbool.h>

#include "disksim.h"
#include "shell_filesystem.h"
#include "shell_entry.h"

struct shell {
	struct shell_command *commands;
	int command_count;

	bool is_mounted;

	struct disk_operations disk;
	struct shell_filesystem filesystem;
	struct shell_fs_operations fops;
	struct shell_entry rootdir, curdir;
};

struct shell *shell_create(void);
int shell_run(struct shell *shell);
void shell_destroy(struct shell *shell);

#endif
