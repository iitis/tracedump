/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "tracedump.h"

static long _ptrace(enum __ptrace_request request, pid_t pid,
	void *addr, void *data,
	const char *func)
{
	long rc;

	rc = ptrace(request, pid, addr, data);

	/* if retval is -1 exit with error, except for PTRACE_PEEK* */
	if (rc == -1 &&
		(errno != 0 || (
			request != PTRACE_PEEKDATA &&
			request != PTRACE_PEEKUSER
	)))
		die("%s(req %d, pid %d): %s\n", func, request, pid, strerror(errno));

	return rc;
}
#define ptrace(a, b, c, d) _ptrace(a, b, ((void *) (c)), ((void *) (d)), __func__)

void ptrace_attach_pid(int pid)
{
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	ptrace_attach_child(pid);
}

void ptrace_attach_child(int pid)
{
	waitpid(pid, NULL, WUNTRACED);
	ptrace(PTRACE_SETOPTIONS, pid, NULL,
		PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
}

void ptrace_traceme(void)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

void ptrace_cont(int pid)
{
	int s;

	ptrace(PTRACE_CONT, pid, NULL, NULL);

	do {
	//	waitpid(pid, &s, WNOHANG);
		waitpid(pid, &s, 0);
	} while (!WIFSTOPPED(s));
}

void ptrace_cont_syscall(int pid)
{
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}

void ptrace_detach(int pid)
{
	ptrace(PTRACE_DETACH, pid , NULL , NULL);
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

	/* TODO: poketext without memcpy? */
	while (count < len) {
		memcpy(&word, vptr+count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count +=4;
	}
}

void ptrace_getregs(int pid, struct user_regs_struct *regs)
{
	ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

void ptrace_setregs(int pid, struct user_regs_struct *regs)
{
	ptrace(PTRACE_SETREGS, pid, NULL, regs);
}
