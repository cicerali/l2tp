/*
 * globals.h
 *
 *  Created on: Mar 8, 2018
 *      Author: cicerali
 */

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <netpacket/packet.h> //sockaddr_ll

#include <stdbool.h>
#include <stdint.h>
#include <control.h>

#define IPMAP_MAX 5000

typedef struct ipmap_t
{
	uint32_t ip_addr;
	session_t *local_session;
}ipmap_t;

int init_globals();

#endif /* GLOBALS_H_ */
