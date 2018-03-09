/*
 * ppp.h
 *
 *  Created on: Mar 5, 2018
 *      Author: cicerali
 */

#ifndef PPP_H_
#define PPP_H_

#define _BSD_SOURCE
#include <stdint.h>
#include <control.h>
#include <log.h>
#include <fsm.h>
#include <parser.h>
#include <data.h>
#include <globals.h>

#define PPPLCP 0xc021
#define PPPPAP 0xc023
#define PPPIPCP 0x8021
#define PPPIPV4 0x0021


typedef enum lcp_codes
{
	CONFIG_REQ = 1,
	CONFIG_ACK,
	CONFIG_NAK,
	CONFIG_REJ,
	TERM_REQ,
	TERM_ACK,
	CODE_REJ,
	PROTO_REJ,
	ECHO_REQ,
	ECHO_REP,
	DISC_REQ
}lcp_codes;

int process_ppp(uint8_t *buf, int length, struct sockaddr_in *remote);

int process_ppp_lcp(session_t *session, uint8_t *buf, int length, struct sockaddr_in *remote);
int process_ppp_pap(session_t *session, uint8_t *buf, int length, struct sockaddr_in *remote);
int process_ppp_ipcp(session_t *session, uint8_t *buf, int length, struct sockaddr_in *remote);

int l2tp_encode_ppp(uint8_t *buf, int buf_size, uint8_t *ppp, int ppp_len,
		uint16_t ppp_type, session_t *session);

int ppp_conf_req(uint8_t *buf, int buf_size);
int ppp_conf_nak(uint8_t *buf, int buf_size);

#endif /* PPP_H_ */
