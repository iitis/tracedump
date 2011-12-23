/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>

#include "utils.h"
#include "ptrace.h"
#include "inject.h"

struct inject *inject_init(void)
{
	struct inject *si;
	int i = 0;
	char *ptr;

	/* GCC trick */
	if (i == 0) goto code_end;

code_start:
asm(
	"jmp data\n\t"

"run_bind:\n\t"
	/* load data */
	"popl   %ecx\n\t"
	"movl   (%ecx), %ebx\n\t"
	"addl   $4, %ecx\n\t"

	/* run socketcall(2) and go back */
	"movl   $102, %eax\n\t"
	"int    $0x80\n\t"
	"int3\n\t"

"data: call run_bind\n\t"
	/* socketcall subcode */
	".long 0x12345678\n\t"

	/* socketcall arguments: fd, *addr, addrlen */
	".long 0x00000000\n\t"  /* fd = 0 */
	".long 0x00000000\n\t"  /* *addr = NULL */
	".long 0x00000010\n\t"  /* addrlen = 16 */

	/* struct sockaddr addr */
	".long 0x0002\n\t"      /* .sin_family = AF_INET */
	".long 0x0000\n\t"      /* .sin_port = 0 */
	".long 0x00000000\n\t"  /* .sin_addr = 0.0.0.0 */
	".long 0x00000000\n\t"  /* .sin_zero */
	".long 0x00000000\n\t"  /* .sin_zero */
);
code_end: if (0); /* GCC trick */

	/* initialize struct inject */
	si = ut_malloc(sizeof(struct inject));

	/* get lengths */
	si->len = &&code_end - &&code_start;
	si->len4 = si->len + (si->len%4 ? (4 - si->len%4) : 0);

	/* copy the code */
	si->code = ut_malloc(si->len4);
	memcpy(si->code, &&code_start, si->len);

	/* find args location */
	for (ptr = si->code + si->len - 4; ptr > si->code; ptr--)
		if (*((uint32_t *) ptr) == 0x12345678)
			break;

	/* save offsets and pointers */
	si->data_offset = (ptr - si->code);
	si->addr_offset = si->data_offset + 16;
	si->data = (uint32_t *) (si->code + si->data_offset);
	si->addr = (struct sockaddr_in *) (si->code + si->addr_offset);
}

void inject_free(struct inject *si)
{
	free(si->code);
	free(si);
}

/* TODO: implement "output" */
int32_t _inject_socketcall(struct inject *si, uint32_t sc_code, bool output, pid_t pid,
	int fd, struct sockaddr_in *sa)
{
	char *backup;
	struct user_regs_struct regs, regs2;

	backup = ut_malloc(si->len4);

	/* make backup */
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	ptrace_read(pid, regs.eip, backup, si->len4);

	/* configure the code */
	si->data[0] = sc_code;
	si->data[1] = fd;
	si->data[2] = regs.eip + si->addr_offset;

	/* inject the code and run it */
	ptrace_write(pid, regs.eip, si->code, si->len4);
	ptrace_cont(pid);

	/* read return code */
	ptrace(PTRACE_GETREGS, pid, NULL, &regs2);

	/* restore the original state */
	ptrace_write(pid, regs.eip, backup, si->len4);
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);

	free(backup);
	return regs2.eax;
}
