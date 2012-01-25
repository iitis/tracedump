/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include "tracedump.h"

struct pid *pid_get(struct tracedump *td, pid_t pid)
{
	struct pid *sp;

	/* speed-up cache */
	if (td->sp && td->sp->pid == pid)
		return td->sp;

	sp = thash_uint_get(td->pids, pid);
	if (!sp) {
		dbg(7, "new pid %d\n", pid);
		sp = mmatic_zalloc(td->mm, sizeof *sp);
		sp->td = td;
		sp->pid = pid;
		thash_uint_set(td->pids, pid, sp);
	}

	return sp;
}

void pid_del(struct tracedump *td, pid_t pid)
{
	dbg(7, "deleting pid %d\n", pid);
	thash_uint_set(td->pids, pid, NULL);
}

void pid_detach_all(struct tracedump *td)
{
	struct pid *sp;
	int status, rc;

	thash_reset(td->pids);
	while ((sp = thash_uint_iter(td->pids, NULL))) {
		/* nice & clean? */
		if (ptrace_detach(sp, 0) == 0) {
			thash_uint_set(td->pids, sp->pid, NULL);
			continue;
		}

		/* ESRCH probably means that the traced process is not in a state appropriate for
		 * PTRACE_DETACH - send it SIGSTOP, wait, and try again */
		if (errno == ESRCH) {
			syscall(SYS_tgkill, pid_tgid(sp->pid), sp->pid, SIGSTOP);
			ptrace_wait(sp, &status);

			if (WIFSTOPPED(status)) {
				switch (WSTOPSIG(status)) {
					case SIGTRAP:
					case SIGSTOP: rc = ptrace_detach(sp, SIGCONT); break;
					default:      rc = ptrace_detach(sp, WSTOPSIG(status)); break;
				}
			} else {
				rc = ptrace_detach(sp, 0);
			}

			/* check if that worked */
			if (rc == 0)
				continue;
		}

		dbg(1, "error while detaching pid %d: %s\n", sp->pid, strerror(errno));
	}
}

int pid_tgid(pid_t pid)
{
	char buf[256];
	FILE *fp;
	int ret = 0;

	snprintf(buf, sizeof buf, "/proc/%d/status", pid);
	fp = fopen(buf, "r");
	if (!fp) {
		dbg(1, "fopen(%s): %s\n", buf, strerror(errno));
		return 0;
	}

	while (fgets(buf, sizeof buf, fp)) {
		if (strncmp("Tgid:", buf, 5) == 0) {
			ret = atoi(buf+6);
			break;
		}
	}

	fclose(fp);
	return ret;
}
