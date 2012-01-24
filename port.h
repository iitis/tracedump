/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PORT_H_
#define _PORT_H_

#include "tracedump.h"

/** Start the garbage collector thread */
void port_init(struct tracedump *td);

/** Stop the garbage collector thread */
void port_deinit(struct tracedump *td);

/** Add port by socket
 * @param local    if true, port in socket is a local port */
void port_add(struct sock *ss, bool local);

#endif
