#ifndef SHELL_COMMAND_H
#define SHELL_COMMAND_H

#include "shell.h"

#include "disksim.h"
#include "shell_entry.h"
#include "shell_filesystem.h"

enum shell_command_condition {
	CMD_COND_NONE	= 0x00,
	CMD_COND_MOUNT	= 0x01,
	CMD_COND_UMOUNT	= 0x02
};

struct shell_command {
	char *name;
	int (*handle)(struct shell *, int, char **);
	enum shell_command_condition conditions;
};

struct shell_command *shell_cmd_list_get_list(void);
int shell_cmd_list_get_size(void);

int shell_cmd_cd(struct shell *shell, int argc, char *argv[]);
int shell_cmd_exit(struct shell *shell, int argc, char *argv[]);
int shell_cmd_mount(struct shell *shell, int argc, char *argv[]);
int shell_cmd_umount(struct shell *shell, int argc, char *argv[]);
int shell_cmd_touch(struct shell *shell, int argc, char *argv[]);
int shell_cmd_fill(struct shell *shell, int argc, char *argv[]);
int shell_cmd_rm(struct shell *shell, int argc, char *argv[]);
int shell_cmd_ls(struct shell *shell, int argc, char *argv[]);
int shell_cmd_format(struct shell *shell, int argc, char *argv[]);
int shell_cmd_df(struct shell *shell, int argc, char *argv[]);
int shell_cmd_mkdir(struct shell *shell, int argc, char *argv[]);
int shell_cmd_rmdir(struct shell *shell, int argc, char *argv[]);
int shell_cmd_mkdirst(struct shell *shell, int argc, char *argv[]);
int shell_cmd_cat(struct shell *shell, int argc, char *argv[]);

#endif
