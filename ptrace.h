/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PTRACE_H_
#define _PTRACE_H_

#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>

/** Attach to process pid */
void ptrace_attach_pid(int pid);

/** Attach to a child which did PTRACE_TRACEME */
void ptrace_attach_child(int pid);

/** Continue execution */
void ptrace_cont(int pid);

/** Detach from process pid */
void ptrace_detach(int pid);

/** Read data from location addr */
void ptrace_read(int pid, unsigned long addr, void *vptr, int len);

/** Write data to location addr */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);

#endif
