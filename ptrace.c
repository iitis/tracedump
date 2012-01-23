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
#include <signal.h>
#include <string.h>
#include <dirent.h>

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
	DIR *dh;
	char buf[128];
	struct dirent *de;

	snprintf(buf, sizeof buf, "/proc/%d/task", pid);
	dh = opendir(buf);

	if (dh) {
		while ((de = readdir(dh))) {
			if (!isdigit(de->d_name[0]))
				continue;

			pid = atoi(de->d_name);
			if (pid <= 0)
				continue;

			ptrace(PTRACE_ATTACH, pid, NULL, NULL);
			ptrace_attach_child(pid);
		}

		closedir(dh);
	} else {
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		ptrace_attach_child(pid);
	}
}

void ptrace_attach_child(int pid)
{
	dbg(1, "attaching PID %d\n", pid);

	waitpid(pid, NULL, __WALL);
	ptrace(PTRACE_SETOPTIONS, pid, NULL,
		PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
	ptrace_cont_syscall(pid, 0, false);
}

void ptrace_traceme(void)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

int ptrace_wait(int pid, int *st)
{
	int rc, status;

	rc = waitpid(pid, &status, __WALL);

	if (rc == -1) {
		dbg(1, "wait(%d): %s\n", pid, strerror(errno));
		return rc;
	}

	if (pid == -1)
		pid = rc;

	if (WIFEXITED(status))
		dbg(1, "wait(%d): process exited with status %d\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		dbg(1, "wait(%d): process terminated with signal %d\n", pid, WTERMSIG(status));
	else if (WIFSTOPPED(status) &&
	         WSTOPSIG(status) != SIGSTOP &&
	         WSTOPSIG(status) != SIGTRAP)
		dbg(1, "wait(%d): process stopped with signal %d\n", pid, WSTOPSIG(status));

	if (st)
		*st = status;

	return rc;
}

static inline void _ptrace_cont(bool syscall, int pid, unsigned long sig, bool w8)
{
	int status;

	while (1) {
		ptrace(syscall ? PTRACE_SYSCALL : PTRACE_CONT, pid, NULL, (void *) sig);
		if (!w8)
			break;

		ptrace_wait(pid, &status);
		if (!WIFSTOPPED(status))
			break;

		sig = WSTOPSIG(status);
		if (sig == SIGSTOP || sig == SIGTRAP)
			break;
	}
}

void ptrace_cont(int pid, unsigned long sig, bool w8) { _ptrace_cont(false, pid, sig, w8); }
void ptrace_cont_syscall(int pid, unsigned long sig, bool w8) { _ptrace_cont(true, pid, sig, w8); }

void ptrace_detach(int pid)
{
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

void ptrace_kill(int pid)
{
	kill(pid, SIGKILL);
}

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
	uint32_t *word;

	word = (uint32_t *) vptr;
	i = count = 0;

	while (count < len) {
		ptrace(PTRACE_POKETEXT, pid, addr + count, *word++);
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
