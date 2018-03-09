/*
 * fsm.c
 *
 *  Created on: Feb 26, 2018
 *      Author: cicerali
 */

#include <fsm.h>

l2tp_fsm_table l2tp_cce_fsm[] =
		{
		{ CCE_IDLE, LOCAL_OPEN_REQUEST, send_SCCRQ, CCE_WAIT_CTL_REPLY },
		{ CCE_IDLE, RECEIVE_SCCRQ_ACCEPT, send_SCCRP, CCE_WAIT_CTL_CONN },
		{ CCE_IDLE, RECEIVE_SCCRQ_DENY, send_StopCCN, CCE_IDLE },
		{ CCE_IDLE, RECEIVE_SCCRP_ACCEPT | RECEIVE_SCCRP_DENY, send_StopCCN,
				CCE_IDLE },
		{ CCE_IDLE, RECEIVE_SCCCN_ACCEPT | RECEIVE_SCCCN_DENY, tunnel_clean_up,
				CCE_IDLE },
				{ CCE_WAIT_CTL_REPLY, RECEIVE_SCCRP_ACCEPT, send_SCCCN,
						CCE_ESTABLISHED },
				{ CCE_WAIT_CTL_REPLY, RECEIVE_SCCRP_DENY, send_StopCCN, CCE_IDLE },
				{ CCE_WAIT_CTL_REPLY, RECEIVE_SCCRQ_LOSE_TIE, requeue_SCCRQ,
						CCE_IDLE },
				{ CCE_WAIT_CTL_REPLY, RECEIVE_SCCCN_ACCEPT, send_StopCCN,
						CCE_IDLE },
				{ CCE_WAIT_CTL_CONN, RECEIVE_SCCCN_ACCEPT, tunnel_open_event,
						CCE_ESTABLISHED },
				{ CCE_WAIT_CTL_CONN, RECEIVE_SCCCN_DENY, send_StopCCN, CCE_IDLE },
				{ CCE_WAIT_CTL_CONN, RECEIVE_SCCRQ_ACCEPT | RECEIVE_SCCRQ_DENY
						| RECEIVE_SCCRP_ACCEPT | RECEIVE_SCCRP_DENY,
						send_StopCCN, CCE_IDLE },
				{ CCE_ESTABLISHED, LOCAL_OPEN_REQUEST, tunnel_open_event,
						CCE_ESTABLISHED },
				{ CCE_ESTABLISHED, ADMIN_TUNNEL_CLOSE, send_StopCCN, CCE_IDLE },
				{ CCE_ESTABLISHED, RECEIVE_SCCRQ_ACCEPT | RECEIVE_SCCRQ_DENY
						| RECEIVE_SCCRP_ACCEPT | RECEIVE_SCCRP_DENY
						| RECEIVE_SCCCN_ACCEPT | RECEIVE_SCCCN_DENY,
						send_StopCCN, CCE_IDLE },
				{ CCE_IDLE | CCE_WAIT_CTL_REPLY | CCE_WAIT_CTL_CONN
						| CCE_ESTABLISHED, RECEIVE_STOPCCN, tunnel_clean_up,
						CCE_IDLE } };

l2tp_fsm_table l2tp_lns_ic_fsm[] =
{
{ LNS_IC_IDLE, RECEIVE_ICRQ_ACCEPT, send_ICRP, LNS_IC_WAIT_CONNECT },
{ LNS_IC_IDLE, RECEIVE_ICRQ_DENY, send_CDN, LNS_IC_IDLE },
{ LNS_IC_IDLE, RECEIVE_ICRP, send_CDN, LNS_IC_IDLE },
{ LNS_IC_IDLE, RECEIVE_ICCN_ACCEPT | RECEIVE_ICCN_DENY, session_clean_up,
		LNS_IC_IDLE },
{ LNS_IC_WAIT_CONNECT, RECEIVE_ICCN_ACCEPT, session_prep_data,
		LNS_IC_ESTABLISHED },
{ LNS_IC_WAIT_CONNECT, RECEIVE_ICCN_DENY, send_CDN, LNS_IC_IDLE },
{ LNS_IC_WAIT_CONNECT, RECEIVE_ICRQ_ACCEPT | RECEIVE_ICRQ_DENY | RECEIVE_ICRP,
		send_CDN, LNS_IC_IDLE },
{ LNS_IC_IDLE | LNS_IC_WAIT_CONNECT | LNS_IC_ESTABLISHED, RECEIVE_CDN,
		session_clean_up, LNS_IC_IDLE },
{ LNS_IC_WAIT_CONNECT | LNS_IC_ESTABLISHED, LOCAL_CLOSE_REQUEST, send_CDN,
		LNS_IC_IDLE },
{ LNS_IC_ESTABLISHED, RECEIVE_ICRQ_ACCEPT | RECEIVE_ICRQ_DENY | RECEIVE_ICRP
		| RECEIVE_ICCN_ACCEPT | RECEIVE_ICCN_DENY, send_CDN, LNS_IC_IDLE }

};

int fsm_cce(int *state, int event_code, void * param1, void * param2,
		void * param3)
{
	int size = sizeof(l2tp_cce_fsm) / sizeof(l2tp_fsm_table);

	for (int i = 0; i < size; i++)
	{
		if ((l2tp_cce_fsm[i].src_state & *state)
				&& (l2tp_cce_fsm[i].evnt_code & event_code))
		{

			int rc = l2tp_cce_fsm[i].action(param1, param2, param3);
			if (rc == 0)
			{
				log_debug("Tunnel state changed from %d to %d", *state,
						l2tp_cce_fsm[i].dst_state);
				*state = l2tp_cce_fsm[i].dst_state;
				return 0;
			}
			log_error(
					"An error occurred during process the event, state not changed!!!");
			return -1;
		}
	}
	log_error("No matching found!!!!!");
	return -2;
}

int fsm_lns_ic(int *state, int event_code, void *param1, void *param2,
		void *param3)
{
	int size = sizeof(l2tp_lns_ic_fsm) / sizeof(l2tp_fsm_table);

	for (int i = 0; i < size; i++)
	{
		if ((l2tp_lns_ic_fsm[i].src_state & *state)
				&& (l2tp_lns_ic_fsm[i].evnt_code & event_code))
		{

			int rc = l2tp_lns_ic_fsm[i].action(param1, param2, param3);
			if (rc == 0)
			{
				log_debug("Session state changed from %d to %d", *state,
						l2tp_lns_ic_fsm[i].dst_state);
				*state = l2tp_lns_ic_fsm[i].dst_state;
				return 0;
			}
			log_error(
					"An error occurred during process the event, state not changed!!!");
			return -1;
		}
	}
	log_error("No matching found!!!!!");
	return -2;
}
