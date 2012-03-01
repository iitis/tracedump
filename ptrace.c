/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include "tracedump.h"

/** ptrace wrapper
 * @retval >=0  success
 * @retval  <0  error, return value is (-1 * errno)
 */
static long _run_ptrace(enum __ptrace_request request, struct pid *sp,
	void *addr, void *data,
	const char *func)
{
	long rc;
	int pid = sp ? sp->pid : 0;

	rc = ptrace(request, pid, addr, data);

	/* rc equal -1 means error */
	if (rc == -1) {
		rc = -errno;

		/* skip errors on some conditions */
		if (errno != 0) {
			if (request == PTRACE_DETACH)
				goto ret;
		} else {
			if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKUSER)
				goto ret;
		}

		dbg(1, "%s(req %d, pid %d): %s\n", func, request, pid, strerror(errno));
	} else {
		dbg(5, "%s(req %d, pid %d)\n", func, request, pid);
	}

ret:
	return rc;
}
#define run_ptrace(a, b, c, d) _run_ptrace(a, b, ((void *) (c)), ((void *) (d)), __func__)

int ptrace_attach_pid(struct pid *sp, void (*cb)(struct pid *sp))
{
	DIR *dh;
	char buf[128];
	struct dirent *de;
	int pid;
	struct pid *sp2;

	snprintf(buf, sizeof buf, "/proc/%d/task", sp->pid);
	dh = opendir(buf);

	if (dh) {
		while ((de = readdir(dh))) {
			if (!isdigit(de->d_name[0]))
				continue;

			pid = atoi(de->d_name);
			if (pid <= 0)
				continue;

			sp2 = pid_get(sp->td, pid);
			run_ptrace(PTRACE_ATTACH, sp2, NULL, NULL);
			if (ptrace_attach_child(sp2, cb) < 0)
				return -1;
		}

		closedir(dh);
	} else {
		run_ptrace(PTRACE_ATTACH, sp, NULL, NULL);
		ptrace_attach_child(sp, cb);
	}

	return 0;
}

int ptrace_attach_child(struct pid *sp, void (*cb)(struct pid *sp))
{
	int rc, status;
	FILE *fp;
	char buf[128];

	rc = waitpid(sp->pid, &status, __WALL);
	if (rc == sp->pid && WIFSTOPPED(status) &&
	   (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTRAP)) {
		/* read PID name */
		snprintf(buf, sizeof buf, "/proc/%d/cmdline", sp->pid);
		fp = fopen(buf, "r");
		fgets(sp->cmdline, sizeof sp->cmdline, fp);
		fclose(fp);

		dbg(1, "attached to PID %d (%s)\n", sp->pid, sp->cmdline);

		/* set ptrace options */
		run_ptrace(PTRACE_SETOPTIONS, sp, NULL,
			PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD);

		/* callback */
		if (cb)
			cb(sp);

		ptrace_cont_syscall(sp, 0, false);
		return 0;
	} else {
		dbg(1, "attaching PID %d failed\n", sp->pid);
		return -1;
	}
}

void ptrace_traceme(void)
{
	run_ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
}

int ptrace_wait(struct pid *sp, int *st)
{
	int rc, status;
	int pid = sp ? sp->pid : -1;

	rc = waitpid(pid, &status, __WALL);

	if (rc == -1) {
		dbg(2, "wait(%d): %s\n", pid, strerror(errno));
		return rc;
	}

	if (pid == -1)
		pid = rc;

	if (WIFEXITED(status))
		dbg(3, "wait(%d): process exited with status %d\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		dbg(2, "wait(%d): process terminated with signal %d\n", pid, WTERMSIG(status));
	else if (WIFSTOPPED(status)) {
		switch (WSTOPSIG(status)) {
			case SIGSTOP:
			case SIGTRAP:
			case SIGTRAPS:
				break;
			case SIGSEGV:
				dbg(1, "wait(%d): process received SIGSEGV - segmentation fault (%s)\n",
					pid, sp->cmdline);
				break;
			default:
				dbg(5, "wait(%d): process received signal %d\n", pid, WSTOPSIG(status));
		}
	}

	if (st)
		*st = status;

	return rc;
}

static inline void _ptrace_cont(bool syscall, struct pid *sp, unsigned long sig, bool w8)
{
	int status;

	while (1) {
		run_ptrace(syscall ? PTRACE_SYSCALL : PTRACE_CONT, sp, NULL, (void *) sig);
		if (!w8)
			break;

		ptrace_wait(sp, &status);
		if (!WIFSTOPPED(status))
			break;

		sig = WSTOPSIG(status);
		if (sig == SIGTRAP || sig == SIGTRAPS)
			break;
	}
}

void ptrace_cont(struct pid *sp, unsigned long sig, bool w8)
{
	_ptrace_cont(false, sp, sig, w8);
}

void ptrace_cont_syscall(struct pid *sp, unsigned long sig, bool w8)
{
	_ptrace_cont(true, sp, sig, w8);
}

void ptrace_detach(struct pid *sp, unsigned long sig)
{
	int status;

	/* are we lucky? */
	if (run_ptrace(PTRACE_DETACH, sp, NULL, (void *) sig) == 0)
		return;

	/* no, the process is not detachable - try to stop it */
	syscall(SYS_tgkill, pid_tgid(sp->pid), sp->pid, SIGSTOP);
	ptrace_wait(sp, &status);

	if (WIFSTOPPED(status)) {
		switch (WSTOPSIG(status)) {
			case SIGSTOP:
			case SIGTRAP:
			case SIGTRAPS:
				run_ptrace(PTRACE_DETACH, sp, NULL, (void *) SIGCONT);
				break;
			default:
				run_ptrace(PTRACE_DETACH, sp, NULL, (void *) WSTOPSIG(status));
		}
	} else {
		run_ptrace(PTRACE_DETACH, sp, NULL, (void *) 0);
	}
}

void ptrace_kill(struct pid *sp)
{
	kill(sp->pid, SIGKILL);
}

void ptrace_read(struct pid *sp, unsigned long addr, void *vptr, int len)
{
	int i , count;
	uint32_t word;
	unsigned long *ptr = (unsigned long *) vptr;

	count = i = 0;

	while (count < len) {
		word = run_ptrace(PTRACE_PEEKTEXT, sp, addr + count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

void ptrace_write(struct pid *sp, unsigned long addr, void *vptr, int len)
{
	int i, count;
	uint32_t *word;

	word = (uint32_t *) vptr;
	i = count = 0;

	while (count < len) {
		run_ptrace(PTRACE_POKETEXT, sp, addr + count, *word++);
		count +=4;
	}
}

void ptrace_getregs(struct pid *sp, struct user_regs_struct *regs)
{
	run_ptrace(PTRACE_GETREGS, sp, NULL, regs);
}

void ptrace_setregs(struct pid *sp, struct user_regs_struct *regs)
{
	run_ptrace(PTRACE_SETREGS, sp, NULL, regs);
}
