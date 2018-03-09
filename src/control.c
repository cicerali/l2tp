/*
 * control.c
 *
 *  Created on: Mar 1, 2018
 *      Author: cicerali
 */
#include <control.h>
#include <ppp.h>

tunnel_t **tunnels;
extern int udp_fd;

void main_loop(void)
{
	uint8_t buf[BUFFER_SIZE];
	struct sockaddr_in remote;
	socklen_t sock_len = sizeof(remote);
	l2tp_control_message message;

	int rc;
	log_info("Waiting message form LAC");
	while (true)
	{
		rc = recvfrom(udp_fd, buf, BUFFER_SIZE, 0, (struct sockaddr*) &remote,
				&sock_len);

		if (rc <= 0)
		{
			log_error(
					"Error occurred, recvfrom rc = %d: udp_fd = %d: error = %s",
					rc, udp_fd, strerror(errno));
			continue;
		}
		if (!(buf[0] & 0x80))
		{
			//log_info("Data message received");
			process_ppp(buf, rc, &remote);
			continue;
		}
		memset(&message, 0, sizeof(l2tp_control_message));
		rc = l2tp_control_decode(buf, rc, &message);
		log_info("Message received, message type %d", message.message_type);
		if (rc != 0)
		{
			log_error("Message parsing error during decode!!!");
			continue;
		}

		// handle messages
		switch (message.message_type)
		{
		case SCCRQ:
		{
			uint16_t tunnel = new_tunnel();
			tunnels[tunnel]->remote_ip = remote;
			tunnels[tunnel]->nr = message.header.ns + 1;
			tunnels[tunnel]->remote_tunnel = message.sccrq.tunnel_id;
			fsm_cce(&tunnels[tunnel]->state, RECEIVE_SCCRQ_ACCEPT, &message,
					&tunnel, &remote);
			tunnels[tunnel]->ns++;
			break;
		}
		case SCCCN:
		{
			uint16_t tunnel = message.header.tunnel_id;
			tunnels[tunnel]->nr = message.header.ns + 1;
			fsm_cce(&tunnels[message.header.tunnel_id]->state,
					RECEIVE_SCCCN_ACCEPT, &message, &tunnel, &remote);
			break;
		}
		case HELLO:
		{
			uint16_t tunnel = message.header.tunnel_id;
			tunnels[tunnel]->nr = message.header.ns + 1;
			hello_ack(&message,
					&tunnel,
					&remote);
			break;
		}
		case ICRQ:
		{
			uint16_t session = new_session(message.header.tunnel_id);
			tunnels[message.header.tunnel_id]->sessions[session].remote_session =
					message.icrq.session_id;
			tunnels[message.header.tunnel_id]->nr = message.header.ns + 1;
			fsm_lns_ic(
					&tunnels[message.header.tunnel_id]->sessions[session].state,
					RECEIVE_ICRQ_ACCEPT, &message,
					&tunnels[message.header.tunnel_id]->sessions[session],
					&remote);
			tunnels[message.header.tunnel_id]->ns++;
			break;
		}
		case ICCN:
		{
			uint16_t session = message.header.session_id;
			tunnels[message.header.tunnel_id]->nr = message.header.ns + 1;
			fsm_lns_ic(
					&tunnels[message.header.tunnel_id]->sessions[session].state,
					RECEIVE_ICCN_ACCEPT, &message,
					&tunnels[message.header.tunnel_id]->sessions[session],
					&remote);
			break;
		}
		case CDN:
		{
			uint16_t session = message.header.session_id;
			tunnels[message.header.tunnel_id]->nr = message.header.ns + 1;
			fsm_lns_ic(
					&tunnels[message.header.tunnel_id]->sessions[session].state,
					RECEIVE_CDN, &message,
					&tunnels[message.header.tunnel_id]->sessions[session],
					&remote);
			break;
		}
		case ZLB:
		{
			log_debug("Zero-Length Body(ZLB) Message");
			break;
		}
		default:
		{
			log_error("Message not supported yet!!!");
			break;
		}
		}
	}

}

void init_tunnels()
{
	tunnels = (tunnel_t **) malloc(MAX_TUNNEL);
	tunnels[0] = (tunnel_t *) malloc(sizeof(tunnel_t));
	for (int i = 1; i < MAX_TUNNEL + 1; i++)
	{
		tunnels[i] = (tunnel_t *) malloc(sizeof(tunnel_t));
		memset(tunnels[i], 0, sizeof(tunnel_t));
		tunnels[i]->state = CCE_IDLE;

		for (int j = 1; j < MAX_SESSION + 1; j++)
		{

			tunnels[i]->sessions[j].state = LNS_IC_IDLE;
		}
	}
	log_info("Allocated size = %dX%d(bytes) = %.4fKB", MAX_TUNNEL, sizeof(tunnel_t), (double)(MAX_TUNNEL*sizeof(tunnel_t))/1024);
	log_info("tunnel initializations done");
}

int send_SCCRQ(void *param1, void *param2, void *param3)
{
	log_debug("send_SCCRQ");
	return 0;
}
int send_SCCRP(void *param1, void *param2, void *param3)
{
	log_debug("send_SCCRP");
	uint16_t tunnel = *(uint16_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[tunnel]->remote_tunnel;
	out_message.header.session_id = 0;
	out_message.header.ns = tunnels[tunnel]->ns;
	out_message.header.nr = tunnels[tunnel]->nr;

	out_message.message_type = SCCRP;
	out_message.sccrp.p_ver.ver = 1;
	out_message.sccrp.p_ver.rev = 0;
	out_message.sccrp.f_cap.asynchronous = false;
	out_message.sccrp.f_cap.synchronous = true;
	memcpy(out_message.sccrp.h_name.value, "netas.test", strlen("netas.test"));
	out_message.sccrp.h_name.length = strlen("netas.test");
	out_message.sccrp.tunnel_id = tunnel;
	out_message.sccrp.b_cap_present = true;
	out_message.sccrp.b_cap.analog = true;
	out_message.sccrp.b_cap.digital = false;
	out_message.sccrp.f_rev_present = true;
	out_message.sccrp.f_rev = 8016;
	out_message.sccrp.v_name_present = true;
	memcpy(out_message.sccrp.v_name.value, "atc", strlen("atc"));
	out_message.sccrp.v_name.length = strlen("atc");
	out_message.sccrp.window_present = true;
	out_message.sccrp.window = 3;
	out_message.sccrp.challenge_present = false;
	out_message.sccrp.c_resp_present = false;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
}

int send_StopCCN(void *param1, void *param2, void *param3)
{
	log_debug("send_StopCCN");
	return 0;
}
int tunnel_clean_up(void *param1, void *param2, void *param3)
{
	log_debug("tunnel_clean_up");
	return 0;
}
int send_SCCCN(void *param1, void *param2, void *param3)
{
	log_debug("send_SCCCN");
	return 0;
}
int requeue_SCCRQ(void *param1, void *param2, void *param3)
{
	log_debug("requeue_SCCRQ");
	return 0;
}
int tunnel_open_event(void *param1, void *param2, void *param3)
{
	log_debug("tunnel_open_event");
	uint16_t tunnel = *(uint16_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[tunnel]->remote_tunnel;
	out_message.header.session_id = 0;
	out_message.header.ns = tunnels[tunnel]->ns;
	out_message.header.nr = tunnels[tunnel]->nr;

	out_message.message_type = ZLB;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
}

int hello_ack(void *param1, void *param2, void *param3)
{
	log_debug("hello_ack");
	uint16_t tunnel = *(uint16_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[tunnel]->remote_tunnel;
	out_message.header.session_id = 0;
	out_message.header.ns = tunnels[tunnel]->ns;
	out_message.header.nr = tunnels[tunnel]->nr;

	out_message.message_type = ZLB;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
}

int send_ICRP(void *param1, void *param2, void *param3)
{
	log_debug("send_ICRP");
	session_t session = *(session_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[session.local_tunnel]->remote_tunnel;
	out_message.header.session_id = session.remote_session;
	out_message.header.ns = tunnels[session.local_tunnel]->ns;
	out_message.header.nr = tunnels[session.local_tunnel]->nr;

	out_message.message_type = ICRP;
	out_message.icrp.session_id = session.local_session;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
}

int send_CDN(void *param1, void *param2, void *param3)
{
	log_debug("send_CDN");
	return 0;
}

int session_clean_up(void *param1, void *param2, void *param3)
{
	log_debug("session_clean_up");
	session_t session = *(session_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[session.local_tunnel]->remote_tunnel;
	out_message.header.session_id = session.remote_session;
	out_message.header.ns = tunnels[session.local_tunnel]->ns;
	out_message.header.nr = tunnels[session.local_tunnel]->nr;

	out_message.message_type = ZLB;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
	return 0;
}

int session_prep_data(void *param1, void *param2, void *param3)
{
	log_debug("session_prep_data");
	session_t session = *(session_t *) param2;
	l2tp_control_message out_message;

	out_message.header.type_flags = 0xC802;
	out_message.header.tunnel_id = tunnels[session.local_tunnel]->remote_tunnel;
	out_message.header.session_id = session.remote_session;
	out_message.header.ns = tunnels[session.local_tunnel]->ns;
	out_message.header.nr = tunnels[session.local_tunnel]->nr;

	out_message.message_type = ZLB;

	return send_control_message(&out_message, (struct sockaddr_in *) param3);
}
int send_control_message(l2tp_control_message *message,
		struct sockaddr_in *remote)
{
	uint8_t buf[BUFFER_SIZE];
	size_t length = 0;
	log_info("Encoding l2tp control message");
	int rc = l2tp_control_encode(buf, &length, message);
	if (rc != 0)
	{
		log_error("Message parsing error during encode!!!");
		return -1;
	}
	socklen_t sock_len = sizeof(struct sockaddr_in);
	rc = sendto(udp_fd, buf, length, 0, (struct sockaddr*) remote, sock_len);
	if (rc <= 0)
	{
		log_info("Error occurred, sendto rc = %d: error: %s", rc,
				strerror(errno));
		return -1;
	}
	return 0;
}
uint16_t new_tunnel()
{
	for (int i = 1; i < MAX_TUNNEL + 1; i++)
	{
		if (!tunnels[i]->inuse)
		{
			tunnels[i]->inuse = true;
			return i;
		}
	}
	return 0;
}

uint16_t new_session(uint16_t tunnel)
{
	for (int i = 1; i < MAX_SESSION + 1; i++)
	{
		if (!tunnels[tunnel]->sessions[i].inuse)
		{
			tunnels[tunnel]->sessions[i].inuse = true;
			tunnels[tunnel]->sessions[i].local_tunnel = tunnel;
			tunnels[tunnel]->sessions[i].local_session = i;
			return i;
		}
	}
	return 0;
}
