#include <stdio.h>
#include <stdlib.h>

#include "shell.h"

int main(int argc, char *argv[])
{
	struct shell *shell;

	shell = shell_create();
	
	while (shell_run(shell)) ;

	shell_destroy(shell);

	return 0;
}
