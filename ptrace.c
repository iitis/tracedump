#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "ptrace.h"

void ptrace_attach_pid(int pid)
{
	if ((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}

	ptrace_attach_child(pid);
}

void ptrace_attach_child(int pid)
{
	waitpid(pid, NULL, WUNTRACED);

	ptrace(PTRACE_SETOPTIONS, pid, NULL,
		PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
}

void ptrace_cont(int pid)
{
	int s;

	if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0) {
		perror("ptrace_cont");
		exit(-1);
	}

	do {
	//	waitpid(pid, &s, WNOHANG);
		waitpid(pid, &s, 0);
	} while (!WIFSTOPPED(s));
}

void ptrace_detach(int pid)
{
	if (ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

/*************
 ************* FIXME: alignment etc. on x86-64 ?
 *************/

void ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int i , count;
	uint32_t word;
	unsigned long *ptr = (unsigned long *) vptr;

	count = i = 0;

	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	uint32_t word;

	i = count = 0;

	while (count < len) {
		memcpy(&word, vptr+count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count +=4;
	}
}
