/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/net.h>
#include <libpjf/main.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "tracedump.h"

struct pid *td_get_pid(struct tracedump *td, pid_t pid)
{
	struct pid *sp;

	/* speed-up cache */
	if (td->sp && td->sp->pid == pid)
		return td->sp;

	sp = thash_uint_get(td->pids, pid);
	if (!sp) {
		dbg(3, "new pid %d\n", pid);
		sp = mmatic_zalloc(td->mm, sizeof *sp);
		sp->pid = pid;

		thash_uint_set(td->pids, pid, sp);
	}

	return sp;
}

void td_del_pid(struct tracedump *td, pid_t pid)
{
	thash_uint_set(td->pids, pid, NULL);
}

/* XXX: it is assumed that sp is entering a socketcall (ie. stopped due to PTRACE_SYSCALL) */
struct sock *td_get_sock(struct tracedump *td, struct pid *sp, int fd)
{
	char buf[128], buf2[128];
	int len, socknum;
	struct sock *ss;
	struct sockaddr_in sa;
	socklen_t optlen;

	/* TODO: speed-up cache? */

	snprintf(buf, sizeof buf, "/proc/%d/fd/%d", sp->pid, fd);
	len = readlink(buf, buf2, sizeof buf2);

	/* is it a socket at all? */
	if (strncmp(buf2, "socket:[", 8) != 0)
		return NULL;

	/* get socknum */
	buf2[len - 1] = 0;
	socknum = atoi(buf2 + 8);

	/* check if in cache */
	if (sp->ss && sp->ss->socknum == socknum)
		return sp->ss;

	/* get socket info */
	ss = thash_uint_get(td->socks, socknum);
	if (!ss) {
		ss = mmatic_zalloc(td->mm, sizeof *ss);
		ss->socknum = socknum;
		thash_uint_set(td->socks, socknum, ss);

		/* exit the original socketcall */
		if (sp->in_socketcall) {
			inject_escape_socketcall(td, sp->pid);
		}

		 /* TODO: handle bind() */

		/* check AF_INET, get local address */
		if (inject_getsockname_in(td, sp->pid, fd, &sa) != 0)
			goto handled;

		/* check TCP/UDP */
		optlen = sizeof ss->type;
		if (inject_getsockopt(td, sp->pid, fd, SOL_SOCKET, SO_TYPE, &ss->type, &optlen) != 0)
			goto handled;
		if (optlen != sizeof ss->type || (ss->type != SOCK_STREAM && ss->type != SOCK_DGRAM))
			goto handled;

		/* autobind if necessary */
		if (!sa.sin_port) {
			if (inject_autobind(td, sp->pid, fd) != 0) {
				dbg(1, "pid %d fd %d: autobind failed\n", sp->pid, fd);
				goto handled;
			}

			if (inject_getsockname_in(td, sp->pid, fd, &sa) != 0) {
				dbg(1, "pid %d fd %d: getsockname after autobind failed\n", sp->pid, fd);
				goto handled;
			}
		}

		printf("port %s %d\n", ss->type == SOCK_STREAM ? "TCP" : "UDP", ntohs(sa.sin_port));

		/* TODO:
		 * - add portnum to BPF
		 */

handled:
		/* finish the original socketcall */
		if (sp->in_socketcall) {
			inject_restore_socketcall(td, sp->pid);
			sp->in_socketcall = false;
		}
	}

	sp->ss = ss;
	return ss;
}

int main(int argc, char *argv[])
{
	mmatic *mm;
	struct tracedump *td;
	pid_t pid;
	struct pid *sp;
	struct sock *ss;
	unsigned long fd_arg;
	struct user_regs_struct regs;
	int status;
	int stopped_pid;

	/*************/

	debug = 5;

	if (argc < 2) {
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit(1);
	}

	/*************/

	if (isdigit(argv[1][0])) {
		/* attach to process */
		pid = atoi(argv[1]);
		ptrace_attach_pid(pid);

		/* TODO: iterate through all the children from procfs and attach */

	} else {
		/* attach to child */
		pid = fork();

		if (pid == 0) {
			ptrace_traceme();
			execvp(argv[1], argv+1);
			exit(123);
		}

		ptrace_attach_child(pid);
	}

	/* TODO: separate /proc/net/udp,tcp garbage collector
	  1. update struct port.last fields
	  2. iterate through td->tcp/udp_ports and delete those with old port.last fields */

	/* TODO: separate PCAP reader thread
	 * on BPF filter update:
	 * 1. cork the socket
	 * 2. read all remaining packets
	 * 3. update the filter
	 * 4. uncork the socket
	 */

	/*************/

	/* initialize */
	mm = mmatic_create();
	td = mmatic_alloc(mm, sizeof *td);
	td->mm = mm;
	td->pid = pid;

	/* create hashing tables */
	td->pids = thash_create_intkey(mmatic_free, td->mm);
	td->socks = thash_create_intkey(mmatic_free, td->mm);
	td->tcp_ports = thash_create_intkey(mmatic_free, td->mm);
	td->udp_ports = thash_create_intkey(mmatic_free, td->mm);

	/*************/

	/* continue the parent process until syscall */
	ptrace_cont_syscall(td->pid, false);

	while (1) {
		/* wait for syscall from any pid */
		/* TODO: process may stop not only due to PTRACE_SYSCALL - check it */
		stopped_pid = waitpid(-1, &status, __WALL);

		if (stopped_pid <= 0) {
			dbg(1, "No more children\n");
			break;
		} else if (WIFEXITED(status)) {
			dbg(1, "PID %d exited with %d\n", stopped_pid, WEXITSTATUS(status));
			td_del_pid(td, stopped_pid);
			continue;
		}

		/* get regs, skip syscalls other than socketcall */
		ptrace_getregs(stopped_pid, &regs);
		if (regs.orig_eax != SYS_socketcall)
			goto next_syscall;

		/* fetch pid info */
		sp = td_get_pid(td, stopped_pid);

		/* filter anything different than bind(), connect() and sendto() */
		sp->code = regs.ebx;
		switch (sp->code) {
			case SYS_BIND:
			case SYS_CONNECT:
			case SYS_SENDTO:
				break;
			default:
				goto next_syscall;
		}

		sp->in_socketcall = !sp->in_socketcall;

		if ((sp->in_socketcall == false && sp->code == SYS_BIND && regs.eax == 0) ||
		    (sp->in_socketcall == true  && sp->code != SYS_BIND)) {
			/* get fd number */
			ptrace_read(stopped_pid, regs.ecx, &fd_arg, 4);
			sp->fd = fd_arg;

			/* get underlying socket */
			ss = td_get_sock(td, sp, sp->fd);

			/* at this moment the socket has been handled */
		}

next_syscall:
		ptrace_cont_syscall(stopped_pid, false);
	}

	/*****************************/

	/* TODO: detach only if Ctrl+C etc. */
	//ptrace_detach(pid);

	mmatic_destroy(mm);

	return 0;
}
