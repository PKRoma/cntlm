/*
 * Credentials related structures and routines for the main module of CNTLM
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

#ifndef _AUTH_H
#define _AUTH_H

#include <stdint.h>
#include "utils.h"

struct auth_s {
	char *user;
	char *domain;
	char *workstation;
	char *passlm;
	char *passnt;
	char *passntlm2;
	int hashntlm2;
	int hashnt;
	int hashlm;
	uint32_t flags;
};

struct auth_s *new_auth(void) {
	struct auth_s *tmp;

	tmp = (struct auth_s *)new(sizeof(struct auth_s));
	tmp->user = new(MINIBUF_SIZE);
	tmp->domain = new(MINIBUF_SIZE);
	tmp->workstation = new(MINIBUF_SIZE);
	tmp->passlm = new(MINIBUF_SIZE);
	tmp->passnt = new(MINIBUF_SIZE);
	tmp->passntlm2 = new(MINIBUF_SIZE);

	return tmp;
}

void free_auth(struct auth_s *creds) {
	if (!creds)
		return;

	free(creds->user);
	free(creds->domain);
	free(creds->workstation);
	free(creds->passlm);
	free(creds->passnt);
	free(creds->passntlm2);
	free(creds);
}

#define auth_strcpy(creds, var, value) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		strlcpy(((creds)->var), (value), MINIBUF_SIZE); \
	} 

#define auth_strncpy(creds, var, value, len) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		strlcpy(((creds)->var), (value), MIN(len, MINIBUF_SIZE)); \
	} 

#define auth_memcpy(creds, var, value, len) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		memcpy(((creds)->var), (value), MIN(len, MINIBUF_SIZE)); \
	} 

struct auth_s *auth_domain(struct auth_s *creds, const char *domain);

#endif /* _AUTH_H */
