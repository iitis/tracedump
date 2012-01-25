/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <libpjf/main.h>
#include "tracedump.h"

static bool EXITING = false;

static void sighandler(int signum)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	EXITING = true;
}

static void handle_socket(struct pid *sp, int fd)
{
	struct tracedump *td = sp->td;
	char buf[128], buf2[128];
	int len, socknum;
	struct sock *ss;
	struct sockaddr_in sa;
	socklen_t optlen;

	/* TODO: speed-up cache? */

	snprintf(buf, sizeof buf, "/proc/%d/fd/%d", sp->pid, fd);
	len = readlink(buf, buf2, sizeof buf2);

	/* is it a socket at all? */
	if (len < 10 || strncmp(buf2, "socket:[", 8) != 0)
		return;

	/* get socknum */
	buf2[len - 1] = 0;
	socknum = atoi(buf2 + 8);

	/* check if in cache */
	if (sp->ss && sp->ss->socknum == socknum)
		return;

	/* get socket info */
	ss = thash_uint_get(td->socks, socknum);
	if (!ss) {
		ss = mmatic_zalloc(td->mm, sizeof *ss);
		ss->td = td;
		ss->socknum = socknum;
		thash_uint_set(td->socks, socknum, ss);

		/* cancel the original socketcall */
		if (sp->in_socketcall)
			inject_escape_socketcall(td, sp);

		/* check if AF_INET, get local address */
		if (inject_getsockname_in(td, sp, fd, &sa) != 0)
			goto handled;

		/* check if TCP/UDP */
		optlen = sizeof ss->type;
		if (inject_getsockopt(td, sp, fd, SOL_SOCKET, SO_TYPE, &ss->type, &optlen) != 0)
			goto handled;
		if (optlen != sizeof ss->type || (ss->type != SOCK_STREAM && ss->type != SOCK_DGRAM))
			goto handled;

		/* autobind if necessary */
		if (!sa.sin_port) {
			if (inject_autobind(td, sp, fd) != 0) {
				dbg(1, "pid %d fd %d: autobind failed\n", sp->pid, fd);
				goto handled;
			}

			if (inject_getsockname_in(td, sp, fd, &sa) != 0) {
				dbg(1, "pid %d fd %d: getsockname after autobind failed\n", sp->pid, fd);
				goto handled;
			}
		}

		ss->port = ntohs(sa.sin_port);

		port_add(ss, true);
		pcap_update(td);

handled:
		/* finish the original socketcall */
		if (sp->in_socketcall) {
			inject_restore_socketcall(td, sp);
			sp->in_socketcall = false;
		}
	}
}

int main(int argc, char *argv[])
{
	mmatic *mm;
	struct tracedump *td;
	pid_t pid;
	struct pid *sp;
	unsigned long fd_arg;
	struct user_regs_struct regs;
	int status;
	int stopped_pid;
	int i;
	struct sigaction sa;

	/*************/

	debug = 5;

	if (argc < 2) {
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit(1);
	}

	/*************/

	/* initialize */
	mm = mmatic_create();
	td = mmatic_zalloc(mm, sizeof *td);
	td->mm = mm;
	pthread_mutex_init(&td->mutex_ports, NULL);

	/* create hashing tables */
	td->pids = thash_create_intkey(mmatic_free, td->mm);
	td->socks = thash_create_intkey(mmatic_free, td->mm);
	td->tcp_ports = thash_create_intkey(mmatic_free, td->mm);
	td->udp_ports = thash_create_intkey(mmatic_free, td->mm);

	/************ attach the victim :) */

	/* handle premature exceptions */
	if ((i = setjmp(td->jmp)) != 0)
		die("exception %d, arg %d\n", EXC_CODE(i), EXC_ARG(i));

	if (isdigit(argv[1][0])) {
		/* attach to process */
		pid = atoi(argv[1]);
		ptrace_attach_pid(pid_get(td, pid));
	} else {
		/* attach to child */
		pid = fork();

		if (pid == 0) {
			ptrace_traceme();
			execvp(argv[1], argv+1);
			exit(123);
		}

		ptrace_attach_child(pid_get(td, pid));
	}

	/************ start threads */

	/* start the garbage collector and sniffer threads */
	port_init(td);
	pcap_init(td);

	/************ main thread */

	/* setup signal handling */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = sighandler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* handle exceptions */
	if ((i = setjmp(td->jmp)) != 0) {
		switch (EXC_CODE(i)) {
			case EXC_PTRACE:
				dbg(1, "ptrace error: pid %d\n", EXC_ARG(i));
				break;
			default:
				dbg(1, "exception %d, arg %d\n", EXC_CODE(i), EXC_ARG(i));
				break;
		}
	}

	while (EXITING == false) {
		/* wait for syscall from any pid */
		stopped_pid = ptrace_wait(NULL, &status);

		/* TODO: filter out our threads :) */

		if (stopped_pid == -1) {
			if (EXITING == true) {
				/* received Ctrl+C / SIGTERM */
				break;
			} else {
				dbg(1, "No more children\n");
				break;
			}
		} else if (WIFEXITED(status) || WIFSIGNALED(status)) {
			pid_del(td, stopped_pid);
			continue;
		}

		/* fetch pid info */
		sp = pid_get(td, stopped_pid);

		/* handle signal passing */
		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGSTOP) {
				/* pass the signal to child */
				ptrace_cont_syscall(sp, WSTOPSIG(status), false);
				continue;
			}
		}

		/* get regs, skip syscalls other than socketcall */
		ptrace_getregs(sp, &regs);
		if (regs.orig_eax != SYS_socketcall)
			goto next_syscall;

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

		/* on exit from a successful bind() or enter to connect()/sendto() */
		if ((sp->in_socketcall == false && sp->code == SYS_BIND && regs.eax == 0) ||
		    (sp->in_socketcall == true  && sp->code != SYS_BIND)) {
			/* get fd number */
			ptrace_read(sp, regs.ecx, &fd_arg, 4);

			/* handle the socket underlying given fd */
			handle_socket(sp, fd_arg);
		}

next_syscall:
		ptrace_cont_syscall(sp, 0, false);
	}

	/*****************************/

	dbg(1, "exiting\n");

	port_deinit(td);
	pcap_deinit(td);
	pid_detach_all(td);
	mmatic_destroy(mm);

	return 0;
}
