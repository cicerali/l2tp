/*
 * ppp.c
 *
 *  Created on: Mar 5, 2018
 *      Author: cicerali
 */

#include <ppp.h>

extern tunnel_t **tunnels;
extern int udp_fd;
extern uint32_t ppp_peer_ip;
extern ipmap_t **ip_map;

int process_ppp(uint8_t *buf, int length, struct sockaddr_in *remote)
{
	uint16_t proto;
	uint16_t h_length = length; // header length for control message
	uint16_t tunnel_id = 0; // tunnel id
	uint16_t session_id = 0; // session id
	uint16_t ns = 0; // sequence number for this data or control message
	uint16_t nr = 0; //	sequence number for expected message to be received
	uint8_t *p_offset = buf + 2; // header length offset

	if (length < 12)
	{
		log_error("Short header, %d bytes", length);
		return -1;
	}

	// Version MUST be 2
	// Version is last 4 bits of flags
	if ((buf[1] & 0x0F) != 2)
	{
		log_error("Unsupported L2TP version: %d", buf[1] & 0x0F);
		return -1;
	}

	// check length bit
	if (buf[0] & 0x40)
	{   // header length
		h_length = be16toh(*(uint16_t * ) p_offset);
		p_offset += 2;
	}

	// tunnel id
	tunnel_id = be16toh(*(uint16_t * ) p_offset);
	p_offset += 2;
	// session id
	session_id = be16toh(*(uint16_t * ) p_offset);
	p_offset += 2;

	// check sequence
	// The S bit MUST be set to 1 for control messages
	if (buf[0] & 0x08)
	{
		// ns
		ns = be16toh(*(uint16_t * ) p_offset);
		p_offset += 2;
		// nr
		nr = be16toh(*(uint16_t * ) p_offset);
		p_offset += 2;
	}

	if (buf[0] & 0x02)
	{
		uint16_t offset = be16toh(*(uint16_t * ) p_offset);
		p_offset += offset + 2;
	}

	if ((p_offset - buf) > h_length)
	{
		log_error("Bad header length value: %d", h_length);
		return -1;
	}

	h_length -= p_offset - buf; //remaining length after skipping header

	if (h_length > 2 && p_offset[0] == 0xff && p_offset[1] == 0x03)
	{
		p_offset += 2;
		h_length -= 2;
	}

	if (h_length < 2)
	{
		log_error("Short ppp length: %d", h_length);
	}

	if (*p_offset & 1)
	{
		proto = *p_offset++;
		h_length--;
	}
	else
	{
		proto = be16toh(*(uint16_t * ) p_offset);
		p_offset += 2;
		h_length -= 2;
	}

	if (!session_id || tunnel_id > MAX_TUNNEL
			|| !(tunnels[tunnel_id]->sessions[session_id].state
					== LNS_IC_ESTABLISHED))
	{
		log_error("Session(%d) not established yet!!!", session_id);
		return -1;
	}
	if (tunnel_id > MAX_TUNNEL || !tunnel_id)
	{
		log_error("Wrong tunnel(%d) id!!!", tunnel_id);
		return -1;
	}

	if (proto == PPPLCP)
	{
		process_ppp_lcp(&tunnels[tunnel_id]->sessions[session_id], p_offset,
				h_length, remote);
	}
	else if (proto == PPPPAP)
	{
		process_ppp_pap(&tunnels[tunnel_id]->sessions[session_id], p_offset,
				h_length, remote);
	}
	else if (proto == PPPIPCP)
	{
		process_ppp_ipcp(&tunnels[tunnel_id]->sessions[session_id], p_offset,
				h_length, remote);
	}
	else if (proto == PPPIPV4)//temp
	{
		process_ppp_ipv4(p_offset, h_length);
	}

	return 0;
}

int process_ppp_ipcp(session_t *session, uint8_t *buf, int length,
		struct sockaddr_in *remote)
{
	uint16_t ipcp_length;
	uint8_t *ipcp_offset = buf;

	if (length < 4)
	{
		log_error("Short IPCP message!!!");
		return -1;
	}

	if ((ipcp_length = be16toh(*(uint16_t * ) (ipcp_offset + 2))) > length)
	{
		log_error("Length mismatch in IPCP!!!");
		return -1;
	}

	if (*ipcp_offset == CONFIG_REQ)
	{
		int opt_lens = ipcp_length - 4;
		uint8_t *opt_offset = ipcp_offset + 4;
		uint8_t *ip_offset = NULL;
		bool send_ack = true;
		bool nak = false;
		while (opt_lens > 2)
		{
			int o_type = opt_offset[0];
			int o_len = opt_offset[1];

			if (o_len == 0 || o_type == 0 || opt_lens < o_len)
			{
				log_error("IPCP option error!!!");
				break;
			}
			switch (o_type)
			{
			case 3: // Ip Address
			{
				log_debug("IPCP Option - Ip Address");
				ip_offset = opt_offset + 2;
				if (*(uint32_t *) (opt_offset + 2) == 0)
				{
					nak = true;
				}
				break;
			}

			default:
			{
				send_ack = false;
				log_error("IPCP - Unimplemented option(%d) received!!!",
						o_type);
				break;
			}
			}
			opt_lens -= o_len;
			opt_offset += o_len;
		}
		if (send_ack)
		{
			// send conf nak
			uint8_t response[1500];
			socklen_t sock_len = sizeof(struct sockaddr_in);
			int rc = 0;
			if (nak)
			{
				uint8_t nak[10];
				rc = ppp_conf_nak(nak, sizeof(nak));
				nak[1] = ipcp_offset[1]; // identifier
				rc = l2tp_encode_ppp(response, sizeof(response), nak, rc,
				PPPIPCP, session);

				//temp
				ip_map[0]->ip_addr = ppp_peer_ip;
				ip_map[0]->local_session = session;

				rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote,
						sock_len);
				if (rc <= 0)
				{
					log_info("Error occurred, sendto rc = %d: error: %s", rc,
							strerror(errno));
					return -1;
				}
			}
			else
			{
				// send conf request
				//uint8_t req[250];
				//rc = ppp_conf_req(req, sizeof(req));
				*ipcp_offset = CONFIG_ACK;
				rc = l2tp_encode_ppp(response, sizeof(response), ipcp_offset,
						ipcp_length, PPPIPCP, session);

				rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote,
						sock_len);
				if (rc <= 0)
				{
					log_info("Error occurred, sendto rc = %d: error: %s", rc,
							strerror(errno));
					return -1;
				}

				*ipcp_offset = CONFIG_REQ;
				*(uint32_t *) (ip_offset) = htobe32(16843010); // 1.1.1.2

				rc = l2tp_encode_ppp(response, sizeof(response), ipcp_offset,
						ipcp_length, PPPIPCP, session);

				rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote,
						sock_len);
				if (rc <= 0)
				{
					log_info("Error occurred, sendto rc = %d: error: %s", rc,
							strerror(errno));
					return -1;
				}
				return 0;

			}

		}
		log_info("IPCP Config Request not implemented yet!!");
	}
	log_info("IPCP(%d) not implemented yet!!", *ipcp_offset);
	return -1;
}

int process_ppp_lcp(session_t *session, uint8_t *buf, int length,
		struct sockaddr_in *remote)
{
	uint16_t lcp_length;
	uint8_t *lcp_offset = buf;

	if (length < 4)
	{
		log_error("Short LCP message!!!");
		return -1;
	}

	if ((lcp_length = be16toh(*(uint16_t * ) (lcp_offset + 2))) > length)
	{
		log_error("Length mismatch in LCP!!!");
		return -1;
	}

	if (*lcp_offset == CONFIG_REQ)
	{
		int opt_lens = lcp_length - 4;
		uint8_t *opt_offset = lcp_offset + 4;
		bool send_ack = true;
		while (opt_lens > 2)
		{
			int o_type = opt_offset[0];
			int o_len = opt_offset[1];

			if (o_len == 0 || o_type == 0 || opt_lens < o_len)
			{
				log_error("LCP option error!!!");
				break;
			}
			switch (o_type)
			{
			case 2: // Async Control Character Map
			{
				log_debug("LCP Option - Async Control Character Map");
				if (be32toh(*(uint32_t * )(opt_offset + 2)))
				{
					send_ack = false;
					log_error(
							"LCP - Async Control Character Map not supported!!!");
				}
				break;
			}
			case 5: // Magic Number
			{
				log_debug("LCP Option - Magic Number");
				break;
			}
			default:
			{
				send_ack = false;
				log_error("LCP - Unimplemented option(%d) received!!!", o_type);
				break;
			}
			}
			opt_lens -= o_len;
			opt_offset += o_len;
		}

		if (send_ack)
		{
			uint8_t response[1500];
			*lcp_offset = CONFIG_ACK;
			int rc = l2tp_encode_ppp(response, sizeof(response), lcp_offset,
					length,
					PPPLCP, session);
			socklen_t sock_len = sizeof(struct sockaddr_in);
			rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote,
					sock_len);
			if (rc <= 0)
			{
				log_info("Error occurred, sendto rc = %d: error: %s", rc,
						strerror(errno));
				return -1;
			}
			// send conf request
			uint8_t req[250];
			rc = ppp_conf_req(req, sizeof(req));
			rc = l2tp_encode_ppp(response, sizeof(response), req, rc, PPPLCP,
					session);
			rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote,
					sock_len);
			if (rc <= 0)
			{
				log_info("Error occurred, sendto rc = %d: error: %s", rc,
						strerror(errno));
				return -1;
			}

			return 0;
		}
		log_info("LCP Config Request not implemented yet!!");
	}
	log_info("LCP(%d) not implemented yet!!", *lcp_offset);
	return -1;
}

int process_ppp_pap(session_t *session, uint8_t *buf, int length,
		struct sockaddr_in *remote)
{
	uint16_t pap_length;
	uint8_t *pap_offset = buf;

	if (length < 4)
	{
		log_error("Short PAP message!!!");
		return -1;
	}

	if ((pap_length = be16toh(*(uint16_t * ) (pap_offset + 2))) > length)
	{
		log_error("Length mismatch in PAP!!!");
		return -1;
	}

	if (*pap_offset != 1)
	{
		log_error("Unexpected PAP code!!!");
		return -1;
	}

	uint8_t pap[5];
	pap[0] = 2;
	pap[1] = 1;
	*(uint16_t *) (pap + 2) = htobe16(5);
	pap[4] = 0;

	// send pap ack
	uint8_t response[1500];
	int rc = l2tp_encode_ppp(response, sizeof(response), pap, 5, PPPPAP,
			session);
	socklen_t sock_len = sizeof(struct sockaddr_in);
	rc = sendto(udp_fd, response, rc, 0, (struct sockaddr*) remote, sock_len);
	if (rc <= 0)
	{
		log_info("Error occurred, sendto rc = %d: error: %s", rc,
				strerror(errno));
		return -1;
	}

	return 0;
}

int ppp_conf_req(uint8_t *buf, int buf_size)
{
	int len = 0;
	uint8_t *offset = buf;

	*offset++ = CONFIG_REQ; // Code
	*offset++ = 1; // Identifier
	offset += 2; // Length
	len += 4;

	// maximum receive unit
	*offset++ = 1;
	*offset++ = 4;
	*(uint16_t*) (offset) = htobe16(1453);
	offset += 2;
	len += 4;

	// auth
	*offset++ = 3;
	*offset++ = 4;
	*(uint16_t*) (offset) = htobe16(0xc023);
	len += 4;

	*(uint16_t*) (buf + 2) = htobe16(len);

	return len;
}

int ppp_conf_nak(uint8_t *buf, int buf_size)
{
	int len = 0;
	uint8_t *offset = buf;

	*offset++ = CONFIG_NAK; // Code
	*offset++ = 1; // Identifier
	offset += 2; // Length
	len += 4;

	// ip address
	*offset++ = 3;
	*offset++ = 6;
	*(uint32_t *) (offset) = htobe32(ppp_peer_ip); // 1.1.1.1
	len += 6;
	*(uint16_t*) (buf + 2) = htobe16(len);

	return len;
}
int l2tp_encode_ppp(uint8_t *buf, int buf_size, uint8_t *ppp, int ppp_len,
		uint16_t ppp_type, session_t *session)
{
	int pack_size = 0;
	uint8_t *offset = buf;
	uint16_t hdr = 0x0002;

	*(uint16_t*) (buf + 0) = htobe16(hdr);
	*(uint16_t*) (buf + 2) = htobe16(
			tunnels[session->local_tunnel]->remote_tunnel);
	*(uint16_t*) (buf + 4) = htobe16(session->remote_session);

	offset += 6;
	pack_size += 6;

	*(uint16_t*) offset = htobe16(0xff03);
	offset += 2;
	pack_size += 2;

//	if (ppp_type < 0x100)
//	{
//		*offset++ = ppp_type;
//		pack_size++;
//	}
//	else
//	{
		*(uint16_t*) offset = htobe16(ppp_type);
		offset += 2;
		pack_size += 2;
	//}

	memcpy(offset, ppp, ppp_len);

	pack_size += ppp_len;
	return pack_size;
}
