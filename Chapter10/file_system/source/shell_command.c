#include "shell_command.h"

#include "shell.h"
#include "shell_entry.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static struct shell_command shell_command_list[] = {
	{	"cd",		shell_cmd_cd,		CMD_COND_MOUNT	},
	{	"exit",		shell_cmd_exit,		CMD_COND_NONE	},
	{	"quit",		shell_cmd_exit,		CMD_COND_NONE	},
	{	"mount",	shell_cmd_mount,	CMD_COND_UMOUNT	},
	{	"umount",	shell_cmd_umount,	CMD_COND_MOUNT	},
	{	"touch",	shell_cmd_touch,	CMD_COND_MOUNT	},
	{	"fill",		shell_cmd_fill,		CMD_COND_MOUNT	},
	{	"rm",		shell_cmd_rm,		CMD_COND_MOUNT	},
	{	"ls",		shell_cmd_ls,		CMD_COND_MOUNT	},
	{	"dir",		shell_cmd_ls,		CMD_COND_MOUNT	},
	{	"format",	shell_cmd_format,	CMD_COND_UMOUNT	},
	{	"df",		shell_cmd_df,		CMD_COND_MOUNT	},
	{	"mkdir",	shell_cmd_mkdir,	CMD_COND_MOUNT	},
	{	"rmdir",	shell_cmd_rmdir,	CMD_COND_MOUNT	},
	{	"mkdirst",	shell_cmd_mkdirst,	CMD_COND_MOUNT	},
	{	"cat",		shell_cmd_cat,		CMD_COND_MOUNT	}
};

struct shell_command *shell_cmd_list_get_list(void) 
{
	return shell_command_list;
}

int shell_cmd_list_get_size(void)
{
	return sizeof(shell_command_list) / sizeof(struct shell_command);
}

int shell_cmd_cd(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry new_entry;
	
	shell->path[0] = shell->rootdir;

	if (argc > 2) {
		printf("usage: %s <directory>\n", argv[0]);
		return 0;
	}

	if (argc == 1) {
		shell->path_top = 0;
		goto SET_CUR_DIR;
	}

	if (strcmp(argv[1], ".") == 0) {
		return 0;
	} else if (strcmp(argv[1], "..") == 0 && shell->path_top > 0) {
		shell->path_top--;
	} else {
		int result = shell->fops.lookup(
			&shell->disk, &shell->fops, 
			&shell->curdir, &new_entry,
			argv[1]
		);

		if ( result != 0) {
			printf("directory not found!\n");
			return -1;
		} else if ( !new_entry.is_dir ) {
			printf("%s is not a directory\n", argv[1]);
			return -1;
		}

		shell->path[++shell->path_top] = new_entry;
	}

SET_CUR_DIR:
	shell->curdir = shell->path[shell->path_top];
	return 0;
}

int shell_cmd_exit(struct shell *shell, int argc, char *argv[])
{
	return -256;
}

int shell_cmd_mount(struct shell *shell, int argc, char *argv[])
{
	int result;

	if (shell->filesystem.mount == NULL) {
		printf("The mount function is NULL\n");
		return 0;
	}

	result = shell->filesystem.mount(
		&shell->disk, &shell->fops, &shell->rootdir
	);
	if (result < 0) {
		printf("%s file system mounting has been failed!\n",
			shell->filesystem.name);
		return -1;
	}

	printf("%s file system has been mounted successfully\n",
		shell->filesystem.name);

	shell->curdir = shell->rootdir;
	shell->is_mounted = true;

	return 0;
}

int shell_cmd_umount(struct shell *shell, int argc, char *argv[])
{
	if (shell->filesystem.mount == NULL)
		return -1;

	shell->is_mounted = false;
	shell->filesystem.umount(&shell->disk, &shell->fops);

	return 0;
}

int shell_cmd_touch(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	int result;

	if (argc < 2) {
		printf("usage: touch <files...>\n");
		return 0;
	}

	result = shell->fops.file_ops.create(
		&shell->disk,
		&shell->fops,
		&shell->curdir,
		argv[1],
		&entry
	);

	if ( result != 0 ) {
		printf("create failed\n");
		return -1;
	}

	return 0;
}

int shell_cmd_fill(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	char *buffer;
	char *tmp;
	int size, result;

	if (argc != 3) {
		printf("usage: fill <file> <size>\n");
		return 0;
	}

	sscanf(argv[2], "%d", &size);

	result = shell->fops.file_ops.create(
		&shell->disk, &shell->fops, &shell->curdir, argv[1], &entry
	);

	if ( result != 0 ) {
		printf("create failed\n");
		return -1;
	}

	buffer = (char *) malloc(size + 13);
	tmp = buffer;

	while (tmp < buffer + size) {
		memcpy(tmp, "can you see? ", 13);
		tmp += 13;
	}

	shell->fops.file_ops.write(
		&shell->disk, &shell->fops, &shell->curdir, 
		&entry, 0, size, buffer
	);

	free(buffer);

	return 0;
}

int shell_cmd_rm(struct shell *shell, int argc, char *argv[])
{
	if (argc < 2) {
		printf("usage: rm <files...>\n");
		return 0;
	}

	for (int i = 1; i < argc; i++) {
		if (shell->fops.file_ops.remove(
				&shell->disk, &shell->fops,
				&shell->curdir, argv[i]
		))
			printf("cannot remove file\n");
	}

	return 0;
}

int shell_cmd_ls(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry_list main;

	if (argc > 2) {
		printf("usage: %s <path...>\n", argv[0]);
		return 0;
	}

	shell_entry_list_init(&main);

	if (shell->fops.read_dir(
			&shell->disk, &shell->fops, &shell->curdir, &main
	)) {
		printf("failed to read_dir()\n");
		return -1;
	}

	printf("%-12s %3s %12s\n", "[File name]", "[D]", "[File size]");
	LIST_ITERATOR_WITH_ENTRY(main.head, entry, struct shell_entry, list)
		printf("%-12s %3d %12d\n",
			entry->name, entry->is_dir, entry->size
		);
	LIST_ITERATOR_END putchar('\n');

	shell_entry_list_release(&main);

	return 0;
}

int shell_cmd_format(struct shell *shell, int argc, char *argv[])
{
	int result;
	char *param = NULL;

	if (argc >= 2)
		param = argv[1];

	result = shell->filesystem.format(&shell->disk, param);

	if (result < 0) {
		printf("%s formatting is failed\n", shell->filesystem.name);
		return -1;
	}

	printf("disk has been formatted successfully\n");

	return 0;
}

double get_percentage(unsigned int number, unsigned int total)
{
	return ((double) number) / total * 100;
}

int shell_cmd_df(struct shell *shell, int argc, char *argv[])
{
	unsigned int used, total;

	shell->fops.stat(&shell->disk, &shell->fops, &total, &used);

	printf("free sectors: %u (%.2lf%%)\t"
	       "used sectors: %u(%.2lf%%)\t"
	       "total: %u\n",
	       total - used, get_percentage(
		       total - used, shell->disk.number_of_sectors
	       ),
	       used, get_percentage(
		       used, shell->disk.number_of_sectors
	       ),
	       total
	);

	return 0;
}

int shell_cmd_mkdir(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	int result;

	if (argc != 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}

	result = shell->fops.mkdir(
		&shell->disk, &shell->fops, &shell->curdir, argv[1], &entry
	);

	if (result) {
		printf("cannot create directory\n");
		return -1;
	}

	return 0;
}

int shell_cmd_rmdir(struct shell *shell, int argc, char *argv[])
{
	int result;

	if (argc != 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}

	result = shell->fops.rmdir(
		&shell->disk, &shell->fops, &shell->curdir, argv[1]
	);

	if ( result != 0 ) {
		printf("cannot remove directory\n");
		return -1;
	}

	return 0;
}

int shell_cd_mkdirst(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	int result, count;

	char buffer[10];

	if (argc != 2) {
		printf("ussage: %s <count>\n", argv[0]);
		return 0;
	}

	sscanf(argv[1], "%d", &count);
	for (int i = 0; i < count; i++) {
		sprintf(buffer, "%d", i);
		result = shell->fops.mkdir(
			&shell->disk, &shell->fops, &shell->curdir,
			(const char *) buffer, &entry
		);

		if (result != 0) {
			printf("cannot create directory\n");
			return -1;
		}
	}

	return 0;
}

int shell_cmd_cat(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	char buffer[BUFSIZ];
	int result;
	unsigned long offset;

	if (argc != 2) {
		printf("usage: %s <file>\n", argv[0]);
		return 0;
	}

	result = shell->fops.lookup(
		&shell->disk, &shell->fops, &shell->curdir, &entry, argv[1]
	);

	if ( result != 0 ) {
		printf("%s lookup failed!\n", argv[1]);
		return -1;
	}

	offset = 0;
	while (shell->fops.file_ops.read(
			&shell->disk, &shell->fops, &shell->curdir,
			&entry, offset, BUFSIZ, buffer) > 0) {
		printf("%s", buffer);
		offset += BUFSIZ;
		memset(buffer, 0x00, BUFSIZ);
	}

	putchar('\n');

	return 0;
}

int shell_cmd_mkdirst(struct shell *shell, int argc, char *argv[])
{
	struct shell_entry entry;
	int result, count;
	char buffer[10];

	if (argc != 2) {
		printf("usage: %s <count>\n", argv[0]);
		return 0;
	}

	sscanf(argv[1], "%d", &count);
	for (int i = 0; i < count; i++) {
		sprintf(buffer, "%d", i);
		result = shell->fops.mkdir(
			&shell->disk, &shell->fops,
			&shell->curdir, buffer, &entry
		);

		if ( result != 0 ) {
			printf("cannot create directory\n");
			return -1;
		}
	}

	return 0;
}
