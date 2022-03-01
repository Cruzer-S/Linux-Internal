#include "shell.h"
/*******************************************************************************
 * include user defined header
 ******************************************************************************/
#include "shell_command.h"
#include "shell_entry.h"
#include "shell_filesystem.h"
#include "disksim.h"

/*******************************************************************************
 * include c standard library
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

/*******************************************************************************
 * preprocessor directives definition
 ******************************************************************************/
#define NUMBER_OF_SECTORS 4096
#define SECTOR_SIZE 512

/*******************************************************************************
 * struct, union, enum definition
 ******************************************************************************/
/* None */

/*******************************************************************************
 * local function declaration
 ******************************************************************************/
static void shell_show_commands(struct shell *shell);
extern void shell_register_filesystem(struct shell_filesystem *);

static bool check_conditions(struct shell *shell, int cmdidx);
static int seperate_string(char *buffer, char *ptrs[]);
static void shell_show_commands(struct shell *shell);

/*******************************************************************************
 * global function definition
 ******************************************************************************/
struct shell *shell_create(void)
{
	struct shell *ret;

	ret = malloc(sizeof(struct shell));
	if ( !ret )
		return NULL;

	ret->commands = shell_cmd_list_get_list();
	ret->command_count = shell_cmd_list_get_size();
	ret->is_mounted = false;
	ret->path_top = 0;

	shell_register_filesystem(&ret->filesystem);

	if (disksim_init(NUMBER_OF_SECTORS, SECTOR_SIZE, &ret->disk) < 0) {
		free(ret);
		return NULL;
	}

	return ret;
}

int shell_run(struct shell *shell)
{
	char buffer[BUFSIZ];
	char *argv[BUFSIZ];
	int argc;

	printf("%s file system shell\n", shell->filesystem.name);

	while (true) {
		if (shell->path_top == 0)
			fputs("[/] # ", stdout);
		else
			printf("[/%s] # ", shell->curdir.name);

		fgets(buffer, BUFSIZ - 1, stdin);
		argc = seperate_string(buffer, argv);

		if (argc == 0)
			continue;

		int i, retval;
		for (i = 0; i < shell->command_count; i++) {
			if (strcmp(shell->commands[i].name, argv[0]) == 0) {
				if (check_conditions(shell, i)) {
					retval = shell->commands[i].handle(
						shell, argc, argv
					);

					if (retval == -256)
						return 0;
				} else {
					puts("this command is currently "
					     "unavailable!\n");
				}

				break;
			}
		}

		if (shell->command_count == i) {
			puts("unknown command!");
			shell_show_commands(shell);
		}
	}

	return -1;
}

void shell_destroy(struct shell *shell)
{
	disksim_uninit(shell->disk);
	free(shell);
}

/*******************************************************************************
 * local function definition
 ******************************************************************************/
bool check_conditions(struct shell *shell, int cmdidx)
{
	if ( (shell->commands[cmdidx].conditions & CMD_COND_MOUNT)
	&&   (!shell->is_mounted) )
		return false;

	if ( (shell->commands[cmdidx].conditions & CMD_COND_UMOUNT)
	&&   (shell->is_mounted) )
		return false;

	return true;
}

void shell_show_commands(struct shell *shell)
{
	printf("* ");
	for (int i = 0; i < shell->command_count; i++) {
		if (i < shell->command_count - 1)
			printf("%s, ", shell->commands[i].name);
		else
			printf("%s", shell->commands[i].name);
	}

	putchar('\n');
}

int seperate_string(char *buffer, char *ptrs[])
{
	char prev = 0;
	int count = 0;

	while ( *buffer ) {
		if (isspace(*buffer))
			*buffer = 0;
		else if (prev == 0)
			ptrs[count++] = buffer;

		prev = *buffer++;
	}

	return count;
}
