/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PTRACE_H_
#define _PTRACE_H_

#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>

#define SIGTRAPS (SIGTRAP | 0x80)

/** Attach to process pid
 * @param cb      call cb before continuing
 * @retval  0     success
 * @retval -1     failed */
int ptrace_attach_pid(struct pid *sp, void (*cb)(struct pid *sp));

/** Attach to a child which did PTRACE_TRACEME
 * @param cb      call cb before continuing
 * @retval  0     success
 * @retval -1     attaching failed */
int ptrace_attach_child(struct pid *sp, void (*cb)(struct pid *sp));

/** Mark this proccess as waiting for ptrace */
void ptrace_traceme(void);

/** Wait for traced child - wrapper around waitpid()
 * @return          pid of the child which has stopped
 * @param status    optional addr for process stop info
 * @param sp        optional - if NULL, wait for any child */
int ptrace_wait(struct pid *sp, int *status);

/** Continue execution until INT3 */
void ptrace_cont(struct pid *sp, unsigned long sig, bool w8);

/** Continue until syscall */
void ptrace_cont_syscall(struct pid *sp, unsigned long sig, bool wait);

/** Detach from process pid */
void ptrace_detach(struct pid *sp, unsigned long sig);

/** Kill traced child */
void ptrace_kill(struct pid *sp);

/** Read data from location addr
 * @len length in bytes */
void ptrace_read(struct pid *sp, unsigned long addr, void *vptr, int len);

/** Write data to location addr
 * @len length in bytes */
void ptrace_write(struct pid *sp, unsigned long addr, void *vptr, int len);

/** Get process registers */
void ptrace_getregs(struct pid *sp, struct user_regs_struct *regs);

/** Set process registers */
void ptrace_setregs(struct pid *sp, struct user_regs_struct *regs);

#endif
