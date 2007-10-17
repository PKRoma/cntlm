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

#include <stdlib.h>
#include "utils.h"
#include "auth.h"

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

void dump_auth(struct auth_s *creds) {
	char *tmp;

	if (!creds) {
		printf("Struct is not allocated!\n");
		return 0;
	}

	printf("User:       %s\n", creds->user);
	printf("Domain:     %s\n", creds->domain);
	printf("Wks:        %s\n", creds->wks);
	tmp = printmem(creds->passntlm2, 21, 8);
	printf("PassNTLMv2: %s\n", tmp);
	free(tmp);
	tmp = printmem(creds->passnt, 21, 8);
	printf("PassNT:     %s\n", tmp);
	free(tmp);
	tmp = printmem(creds->passlm, 21, 8);
	printf("PassLM:     %s\n", tmp);
	free(tmp);
}
