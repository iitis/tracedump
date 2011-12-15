#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "inject.h"
#include "ptrace.h"

int main(int argc, char *argv[])
{
	pid_t pid;
	int fd;
	struct inject *si;

	if (argc != 3) {
		printf("Usage: %s <pid to be traced> <fd>\n", argv[0]);
		exit(1);
	}

	pid = atoi(argv[1]);
	fd = atoi(argv[2]);

	/* attach */
	ptrace_attach(pid);

	/* do the dirty work */
	si = inject_init();
	inject_autobind(si, pid, 3);

	/* detach */
	ptrace_detach(pid);

	return 0;
}
