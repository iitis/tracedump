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
#include "inject.h"
#include "ptrace.h"

struct pid *td_get_pid(struct tracedump *td, pid_t pid)
{
	struct pid *sp;

	/* TODO: speed-up with some cache? */

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

	/* TODO: speed-up cache? */

	snprintf(buf, sizeof buf, "/proc/%d/fd/%d", sp->pid, fd);
	len = readlink(buf, buf2, sizeof buf2);

	/* is it a socket at all? */
	if (strncmp(buf2, "socket:[", 8) != 0)
		return NULL;

	/* get socknum */
	buf2[len - 1] = 0;
	socknum = atoi(buf2 + 8);

	/* get socket info */
	ss = thash_uint_get(td->socks, socknum);
	if (!ss) {
		ss = mmatic_zalloc(td->mm, sizeof *ss);
		ss->socknum = socknum;

		/* TODO: new socket */
		printf("                TODO ==> new socket %d <== TODO\n", ss->socknum);

		/* TODO:
		 * ! Remember that sp is stopped and is entering a socketcall !
		 *
		 * - check if AF_INET and SOCK_STREAM or SOCK_DGRAM
		 * - check portnum - addr from bind() or from an additional getsockname()
		 * - if its 0, than do autobind() + getsockname() once again
		 *
		 * - add portnum to BPF
		 */

		thash_uint_set(td->socks, socknum, ss);
	}

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
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			execvp(argv[1], argv+1);
			exit(123);
		}

		ptrace_attach_child(pid);
	}

	/* TODO: check for ptrace errors */

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
	/* TODO: better ptrace.c API, integration and error checking */
	ptrace(PTRACE_SYSCALL, td->pid, NULL, NULL);

	while (1) {
		/* wait for syscall from any pid */
		stopped_pid = waitpid(-1, &status, __WALL);

		if (stopped_pid <= 0) {
			dbg(1, "No more children\n");
			break;
		} else if (WIFEXITED(status)) {
			dbg(1, "PID %d exited with %d\n", stopped_pid, WEXITSTATUS(status));
			td_del_pid(td, stopped_pid);
			continue;
		}

		/* TODO: may stop here not only due to PTRACE_SYSCALL - check it */
//		if (stopped_pid <= 0 || (WIFEXITED(status) && stopped_pid == pid))

		/* get process registers */
		ptrace(PTRACE_GETREGS, stopped_pid, NULL, &regs);

		/* skip syscalls other than socketcall */
		if (regs.orig_eax != SYS_socketcall) {
			goto next_syscall;
		}

		/* filter anything different than bind(), connect() and sendto() */
		sp = td_get_pid(td, stopped_pid);
		sp->code = regs.ebx;

		/* filter by socketcall code */
		switch (sp->code) {
			case SYS_BIND:
			case SYS_CONNECT:
			case SYS_SENDTO:
				break;
			default:
				goto next_syscall;
		}

		/* inspect the process */
		if (sp->in_socketcall) {
			/* process has left a socketcall */
			sp->in_socketcall = false;

			/* TODO: check return code: regs.eax */
		} else {
			/* process has entered a socketcall */
			sp->in_socketcall = true;

			/* get fd number */
			ptrace_read(stopped_pid, regs.ecx, &fd_arg, 4);
			sp->fd = fd_arg;

			/* get underlying socket */
			ss = td_get_sock(td, sp, sp->fd);

			/* at this moment the socket has been handled */
		}

next_syscall:
		/* continue until next syscall entry/exit */
		ptrace(PTRACE_SYSCALL, stopped_pid, NULL, NULL);
	}

	/*****************************/

	/* TODO: detach only if Ctrl+C etc. */
	//ptrace_detach(pid);

	mmatic_destroy(mm);

	return 0;
}
