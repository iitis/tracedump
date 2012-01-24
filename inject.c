/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <stdarg.h>

#include "tracedump.h"

int32_t inject_socketcall(struct tracedump *td, struct pid *sp, uint32_t sc_code, ...)
{
	/* int 0x80, int3 */
	unsigned char code[4] = { 0xcd, 0x80, 0xcc, 0 };
	char backup[4];
	struct user_regs_struct regs, regs2;
	int ss_vals, ss_mem, ss;
	va_list vl;
	enum arg_type type;
	uint32_t sv;
	void *ptr;
	uint8_t *stack, *stack_mem;
	uint32_t *stack32;
	int i, j;

	/*
	 * get the required amount of stack space
	 */
	ss_vals = 0;
	ss_mem = 0;
	va_start(vl, sc_code);
	do {
		type = va_arg(vl, enum arg_type);
		if (type == AT_LAST) break;
		sv  = va_arg(vl, uint32_t);

		/* each socketcall argument takes 4 bytes */
		ss_vals += 4;

		/* if its memory, it takes additional sv bytes */
		if (type == AT_MEM_IN || type == AT_MEM_INOUT) {
			ss_mem += sv;
			ptr = va_arg(vl, void *);
		}
	} while (true);
	va_end(vl);
	ss = ss_vals + ss_mem;

	/*
	 * backup
	 */
	ptrace_getregs(sp, &regs);
	memcpy(&regs2, &regs, sizeof regs);
	ptrace_read(sp, regs.eip, backup, sizeof backup);

	/*
	 * write the stack
	 */
	stack = mmatic_zalloc(td->mm, ss);
	stack32 = (uint32_t *) stack;
	stack_mem = stack + ss_vals;

	va_start(vl, sc_code);
	i = 0; j = 0;
	do {
		type = va_arg(vl, enum arg_type);
		if (type == AT_LAST) break;

		sv  = va_arg(vl, uint32_t);

		if (type == AT_VALUE) {
			stack32[i++] = sv;
		} else { /* i.e. its a memory arg */
			stack32[i++] = regs.esp - ss_mem + j;

			/* copy the memory */
			ptr = va_arg(vl, void *);
			memcpy(stack_mem + j, ptr, sv);
			j += sv;
		}
	} while (true);
	va_end(vl);

	ptrace_write(sp, regs.esp - ss, stack, ss);

	/*
	 * write the code and run
	 */
	regs2.eax = 102; // socketcall
	regs2.ebx = sc_code;
	regs2.ecx = regs.esp - ss;

	ptrace_write(sp, regs.eip, code, sizeof code);
	ptrace_setregs(sp, &regs2);
	ptrace_cont(sp, 0, true);

	/*
	 * read back
	 */
	ptrace_getregs(sp, &regs2);
	ptrace_read(sp, regs.esp - ss_mem, stack_mem, ss_mem);

	va_start(vl, sc_code);
	do {
		type = va_arg(vl, enum arg_type);
		if (type == AT_LAST) break;

		sv = va_arg(vl, uint32_t);
		if (type == AT_VALUE) continue;

		ptr = va_arg(vl, void *);
		if (type == AT_MEM_IN) continue;

		memcpy(ptr, stack_mem, sv);
		stack_mem += sv;
	} while (true);
	va_end(vl);

	/* restore */
	ptrace_write(sp, regs.eip, backup, sizeof backup);
	ptrace_setregs(sp, &regs);

	mmatic_free(stack);

	return regs2.eax;
}

void inject_escape_socketcall(struct tracedump *td, struct pid *sp)
{
	struct user_regs_struct regs;

	/* make backup */
	ptrace_getregs(sp, &regs);
	memcpy(&sp->regs, &regs, sizeof regs);

	/* update EBX so it is invalid */
	regs.ebx = 0;
	ptrace_setregs(sp, &regs);

	/* run the invalid socketcall and wait */
	ptrace_cont_syscall(sp, 0, true);

	/* -> now the process is in user mode */
}

void inject_restore_socketcall(struct tracedump *td, struct pid *sp)
{
	/* int 0x80, int3 */
	unsigned char code[4] = { 0xcd, 0x80, 0xcc, 0 };
	char backup[4];
	struct user_regs_struct regs2;

	/* backup */
	ptrace_read(sp, sp->regs.eip, backup, 4);

	/* exec */
	sp->regs.eax = sp->regs.orig_eax;
	ptrace_setregs(sp, &sp->regs);
	ptrace_write(sp, sp->regs.eip, code, 4);
	ptrace_cont(sp, 0, true);

	/* read the return code */
	ptrace_getregs(sp, &regs2);
	sp->regs.eax = regs2.eax;

	/* restore */
	ptrace_setregs(sp, &sp->regs);
	ptrace_write(sp, sp->regs.eip, backup, 4);
}
