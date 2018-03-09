/*
 * fsm.h
 *
 *  Created on: Feb 26, 2018
 *      Author: cicerali
 */

#ifndef FSM_H_
#define FSM_H_
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <log.h>
#include <control.h>
#include <parser.h>
#include <test.h>

typedef enum cce_state_codes
{
	CCE_IDLE = 0x01, CCE_WAIT_CTL_REPLY = 0x02, CCE_WAIT_CTL_CONN = 0x04, CCE_ESTABLISHED = 0x08
} cce_state_codes;


int fsm_cce(int *state, int event_code, void *param1, void *param2, void *param3);

typedef enum cce_events
{
	LOCAL_OPEN_REQUEST = 0x01,
	RECEIVE_SCCRQ_ACCEPT = 0x02,
	RECEIVE_SCCRQ_DENY = 0x04,
	RECEIVE_SCCRP_ACCEPT = 0x08,
	RECEIVE_SCCCN_ACCEPT = 0x10,
	RECEIVE_SCCRP_DENY = 0x20,
	RECEIVE_SCCRQ_LOSE_TIE = 0x40,
	RECEIVE_SCCCN_DENY = 0x80,
	ADMIN_TUNNEL_CLOSE = 0x100,
	RECEIVE_STOPCCN = 0x200
} cce_events;

typedef enum lns_ic_state_codes
{
	LNS_IC_IDLE = 0x01, LNS_IC_WAIT_CONNECT = 0x02, LNS_IC_ESTABLISHED = 0x04
} lns_ic_state_codes;

int fsm_lns_ic(int *state, int event_code, void *param1, void *param2, void *param3);

typedef enum lns_ic_events
{
	RECEIVE_ICRQ_ACCEPT = 0x01,
	RECEIVE_ICRQ_DENY = 0x02,
	RECEIVE_ICRP = 0x04,
	RECEIVE_ICCN_ACCEPT = 0x08,
	RECEIVE_ICCN_DENY = 0x10,
	RECEIVE_CDN = 0x20,
	LOCAL_CLOSE_REQUEST = 0x40
} lns_ic_events;

typedef struct l2tp_fsm_table
{
	int src_state;
	int evnt_code;
	int (*action)(void *param1, void *param2, void *param3);
	int dst_state;
} l2tp_fsm_table;




#endif /* FSM_H_ */
