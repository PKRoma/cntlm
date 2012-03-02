/*
 * These are socket routines for the main module of CNTLM
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2007 David Kubicek
 *
 */

#ifndef _SOCKET_H
#define _SOCKET_H

#include <netinet/in.h>
#include <stdint.h>

#include "config/config.h"

#if config_socklen_t != 1
#define socklen_t uint32_t
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

extern int so_resolv(struct in_addr *host, const char *name);
extern int so_connect(struct in_addr host, int port);
extern int so_listen(int port, struct in_addr source);
extern int so_dataready(int fd);
extern int so_closed(int fd);
extern int so_recvln(int fd, char **buf, int *size);

#endif /* _SOCKET_H */
