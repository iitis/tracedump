/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
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

static void _prepare(struct pid *sp)
{
	FILE *fp;
	char buf[128];
	unsigned char code[4] = { 0xcd, 0x80, 0, 0 }; // int 0x80

	if (sp->vdso_addr)
		return;

	/* find VDSO address */
	snprintf(buf, sizeof buf, "/proc/%d/maps", sp->pid);
	fp = fopen(buf, "r");
	while (fgets(buf, sizeof buf, fp)) {
		if (strlen(buf) < 49 + 6)
			continue;

		/* found it? */
		if (strncmp(buf + 49, "[vdso]", 6) == 0) {
			/* parse address */
			buf[8] = 0;
			sp->vdso_addr = strtoul(buf, NULL, 16);
			break;
		}
	}
	fclose(fp);

	if (!sp->vdso_addr)
		dbg(0, "pid %d: no [vdso] memory region\n", sp->pid);

#ifdef VDSO_PIGGYBACK
	/* on x86-32 the INT 0x80 is already there :) */
	sp->vdso_addr += 0x406;
#else
	/* inject our code */
	dbg(3, "pid %d: installing code at 0x%x\n", sp->pid, sp->vdso_addr);
	ptrace_write(sp, sp->vdso_addr, code, sizeof code);
#endif
}

int32_t inject_socketcall(struct tracedump *td, struct pid *sp, uint32_t sc_code, ...)
{
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
	ss_vals = 0;  // stack space for immediate values
	ss_mem = 0;   // stack space for pointer values
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

	/*
	 * write the stack
	 */
	stack = mmatic_zalloc(td->mm, ss); // stack area for immediate values
	stack32 = (uint32_t *) stack;
	stack_mem = stack + ss_vals;       // stack area for pointer values

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
	_prepare(sp);

	regs2.eax = 102;            // socketcall
	regs2.ebx = sc_code;
	regs2.ecx = regs.esp - ss;
	regs2.eip = sp->vdso_addr;  // gateway to int3

	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

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
	struct user_regs_struct regs2;

	/* prepare */
	_prepare(sp);
	memcpy(&regs2, &sp->regs, sizeof regs2);
	regs2.eax = sp->regs.orig_eax;
	regs2.eip = sp->vdso_addr;

	/* exec */
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);
	ptrace_cont_syscall(sp, 0, true);

	/* rewrite the return code */
	ptrace_getregs(sp, &regs2);
	sp->regs.eax = regs2.eax;

	/* restore */
	ptrace_setregs(sp, &sp->regs);
}
