#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>

typedef bool command_func(int argc, char *argv[]);

struct command {
	char *name;
	char *desc;
	command_func *func;
};

command_func command_cd, command_exit, command_help;

struct command builtin_commnads [] = {
	{ "cd",		"change directory",	command_cd },
	{ "exit",	"exit this shell",	command_exit },
	{ "quit",	"quit tihs shell",	command_exit },
	{ "help",	"show this help",	command_help },
	{ "?",		"show this help",	command_help }
};

const int builtin_commnads_size =   sizeof(builtin_commnads) 
				  / sizeof(struct command);

bool command_cd(int argc, char *argv[])
{
	if (argc == 1) {
		chdir(getenv("HOME"));
	} else if (argc == 2) {
		if (chdir(argv[1]))
			printf("No directory\n");
	} else printf("USAGE: cd [dir]\n");

	return true;
}

bool command_exit(int argc, char *argv[])
{
	return false;
}

bool command_help(int argc, char *argv[])
{
	for (int i = 0; i < builtin_commnads_size; i++)
		printf("%-10s: %s\n", builtin_commnads[i].name,
				      builtin_commnads[i].desc);

	return true;
}

int tokenize(char *buf, char *delims, char *tokens[], int maxTokens)
{
	int count = 0;
	char *token;

	token = strtok(buf, delims);
	while (token != NULL && count < maxTokens) {
		tokens[count] = token;
		count++;
		token = strtok(NULL, delims);
	}

	tokens[count] = NULL;

	return count;
}

bool run(char *line)
{
	const char delims[] = " \r\n\t";
	char *tokens[128];
	int token_count;
	int status;
	pid_t child;

	token_count = tokenize(line, (char *) delims,
			       tokens, sizeof(tokens) / sizeof(char *));
	if (token_count == 0)
		return true;

	for (int i = 0; i < builtin_commnads_size; i++) {
		if (strcmp(builtin_commnads[i].name, tokens[0]) == 0)
			return builtin_commnads[i].func(token_count, tokens);
	}

	child = fork();
	if (child == 0) {
		execvp(tokens[0], tokens);
		printf("No such file\n");
	} else if (child < 0) {
		printf("Failed to fork()\n");
		exit(EXIT_FAILURE);
	} else wait(&status);

	return true;
}

int main(void)
{
	char line[1024];

	while (true) {
		printf("%s $ ", get_current_dir_name());
		fgets(line, sizeof(line) - 1, stdin);
		if (run(line) == false)
			break;
	}

	return 0;
}
