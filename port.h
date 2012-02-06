/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
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

/** Get list of all local ports from procfs
 * @param tcp    if true, list for TCP; UDP otherwise
 * @retval NULL  error
 * @note allocates memory in td->mm */
void *port_list(struct tracedump *td, bool tcp);

#define PORT_SET(list, port) list[port/8] |= 1 << (port%8)
#define PORT_ISSET(list, port) ((list[port/8] >> (port%8)) & 1)

#endif
