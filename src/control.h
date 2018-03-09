/*
 * control.h
 *
 *  Created on: Mar 1, 2018
 *      Author: cicerali
 */

#ifndef CONTROL_H_
#define CONTROL_H_

#include <stdbool.h>

#include <fsm.h>
#include <l2tp.h>
#include <parser.h>

#define MAX_TUNNEL 100
#define MAX_SESSION 1000

typedef struct session_t
{
	int state;
	bool inuse;
	uint16_t local_session;
	uint16_t remote_session;
	uint16_t local_tunnel;
}session_t;

typedef struct tunnel_t
{
	int state;
	bool inuse;
	struct sockaddr_in remote_ip;
	uint16_t remote_tunnel;
	uint16_t ns;
	uint16_t nr;
	session_t sessions[MAX_SESSION];
}tunnel_t;

void main_loop(void);
void init_tunnels();

uint16_t new_tunnel();
uint16_t new_session(uint16_t tunnel);

int send_SCCRQ(void *param1, void *param2, void *param3);
int send_SCCRP(void *param1, void *param2, void *param3);
int send_StopCCN(void *param1, void *param2, void *param3);
int tunnel_clean_up(void *param1, void *param2, void *param3);
int send_SCCCN(void *param1, void *param2, void *param3);
int requeue_SCCRQ(void *param1, void *param2, void *param3);
int tunnel_open_event(void *param1, void *param2, void *param3);
int hello_ack(void *param1, void *param2, void *param3);

int send_ICRP(void *param1, void *param2, void *param3);
int send_CDN(void *param1, void *param2, void *param3);
int session_clean_up(void *param1, void *param2, void *param3);
int session_prep_data(void *param1, void *param2, void *param3);

int send_control_message(l2tp_control_message *message, struct sockaddr_in *remote);

#endif /* CONTROL_H_ */
