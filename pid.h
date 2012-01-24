/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PID_H_
#define _PID_H_

#include "tracedump.h"

/** Get struct pid for given pid number */
struct pid *pid_get(struct tracedump *td, pid_t pid);

/** Remove given pid from the database */
void pid_del(struct tracedump *td, pid_t pid);

/** Detach from all pids */
void pid_detach_all(struct tracedump *td);

#endif
