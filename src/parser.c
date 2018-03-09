/*
 * parser.c
 *
 *  Created on: Feb 17, 2018
 *      Author: cicerali
 */

#include <parser.h>

int l2tp_control_decode(const uint8_t *mbuf, const size_t length,
		l2tp_control_message *l2tp_msg)
{
	uint16_t h_length = 0; // header length for control message
	uint16_t avps_length = 0; // length after skipping header
	uint16_t tunnel_id = 0; // tunnel id
	uint16_t session_id = 0; // session id
	uint16_t ns = 0; // sequence number for this data or control message
	uint16_t nr = 0; //	sequence number for expected message to be received
	const uint8_t *p_offset = mbuf + 2; // header length offset

	// check mandatory AVPs exists

	t_random_vector r_vector;
	r_vector.length = 0;

	uint16_t avp_type = 0; //  avp type
	uint16_t message_type = UINT16_MAX; //message type

	// minumum l2tp header size 6 byte
	// minimum l2tp control header size 12 bytes
	// Flags, Length, Tunnel ID, Session ID, Ns, Nr(12 bytes)
	if (length < 12)
	{
		log_error("Short header, %d bytes", length);
		return -1;
	}

	// Version MUST be 2
	// Version is last 4 bits of flags
	if ((mbuf[1] & 0x0F) != 2)
	{
		log_error("Unsupported L2TP version: %d", mbuf[1] & 0x0F);
		return -1;
	}

	// only handle control messages
	// flags 1st bit MUST be 1
	if (mbuf[0] & 0x80)
	{
		// flags
		l2tp_msg->header.type_flags = be16toh(*(uint16_t * ) mbuf);

		// check length bit
		if (mbuf[0] & 0x40)
		{   // header length
			h_length = be16toh(*(uint16_t * ) p_offset);
			p_offset += 2;
		}
		else
		{
			log_error("Length(L)  bit MUST be set to 1 for control messages");
			return -1;
		}

		// tunnel id
		tunnel_id = be16toh(*(uint16_t * ) p_offset);
		l2tp_msg->header.tunnel_id = tunnel_id;
		p_offset += 2;
		// session id
		session_id = be16toh(*(uint16_t * ) p_offset);
		l2tp_msg->header.session_id = session_id;
		p_offset += 2;

		// check sequence
		// The S bit MUST be set to 1 for control messages
		if (mbuf[0] & 0x08)
		{
			// ns
			ns = be16toh(*(uint16_t * ) p_offset);
			l2tp_msg->header.ns = ns;
			p_offset += 2;
			// nr
			nr = be16toh(*(uint16_t * ) p_offset);
			l2tp_msg->header.nr = nr;
			p_offset += 2;
		}
		else
		{
			log_error("Sequence(S) bit MUST be set to 1 for control messages");
			return -1;
		}

		// check offset
		if (mbuf[0] & 0x02)
		{
			log_error("Offset(O) bit MUST be set to 0 for control message");
			return -1;
		}

		// check priority
		if (mbuf[0] & 0x01)
		{
			log_error("Priority (P) bit MUST be set to 0 for control message");
			return -1;
		}

		avps_length = h_length - 12; // skip header

		// check ZLB
		if(avps_length < 0)
		{
			log_error("Message size less than expected");
		}
		else if (avps_length == 0)
		{
			//log_debug("Zero-Length Body (ZLB) Message");
			message_type = ZLB;
			l2tp_msg->message_type = message_type;
			return 0;
		}

		// decode first AVP
		// The Message Type AVP MUST be the first AVP in a message
		// Message Type (All Messages)
		uint16_t avp_length = 0; // 12 bit length
		const uint8_t *avp_offset = NULL; // avp offset
		uint8_t flags = 0; // AVP flags
		bool first_avp = true;

		while (avps_length > 0)
		{
			avp_length = (be16toh(*(uint16_t *) p_offset) & 0x3FF);
			avp_offset = p_offset;
			flags = *p_offset;
			if (avp_length > avps_length)
			{
				log_error("Invalid length in AVP");
				return -1;
			}

			// reserved bits(xx00 00xx), should be clear
			if ((flags & 0x3C) && first_avp)
			{
				log_error("Unrecognised AVP flags(%02X) in first AVP", flags);
				return -1;
			}
			if (flags & 0x40) //hidden AVPs
			{
				// to do
				log_error("Hidden AVP not supported");
				return -1;
			}

			avp_offset += 2;

			// only IETF supported
			if (*(uint16_t *) (avp_offset))
			{
				log_error("Unknown AVP vendor %u",
						be16toh(*(uint16_t * ) (avp_offset)));
				return -1;
			}

			avp_offset += 2;
			// type is 3rd byte
			avp_type = be16toh(*(uint16_t * ) (avp_offset));
			if (first_avp && avp_type != MESSAGE_TYPE)
			{
				log_error(
						"Message Type AVP MUST be the first AVP in a message");
				return -1;
			}
			first_avp = false;
			avp_offset += 2;

			// process AVPs
			switch (avp_type)
			{
			case MESSAGE_TYPE: // Message Type (All Messages)
			{
				message_type = be16toh(*(uint16_t * ) (avp_offset));
				l2tp_msg->message_type = message_type;
				break;
			}
			case RESULT_CODE: // Result Code (CDN, StopCCN)
			{
				uint16_t rescode = be16toh(*(uint16_t * ) avp_offset);
				avp_offset += 2;

				if (message_type == StopCCN)
				{
					l2tp_msg->stopccn.r_code.code = rescode;
					if (avp_length == 10)
					{
						l2tp_msg->stopccn.r_code.error_present = true;
						l2tp_msg->stopccn.r_code.error = be16toh(
								*(uint16_t * ) avp_offset);
						avp_offset += 2;
					}
					else if (avp_length > 10)
					{
						l2tp_msg->stopccn.r_code.error_present = true;
						l2tp_msg->stopccn.r_code.error = be16toh(
								*(uint16_t * ) avp_offset);
						avp_offset += 2;
						l2tp_msg->stopccn.r_code.error_massage_present = true;
						l2tp_msg->stopccn.r_code.length = avp_length - 10;
						memcpy(l2tp_msg->stopccn.r_code.error_massage,
								avp_offset, l2tp_msg->stopccn.r_code.length); // check max
					}
				}
				else if (message_type == CDN)
				{
					l2tp_msg->cdn.r_code.code = rescode;
					if (avp_length == 10)
					{
						l2tp_msg->cdn.r_code.error_present = true;
						l2tp_msg->cdn.r_code.error = be16toh(
								*(uint16_t * ) avp_offset);
						avp_offset += 2;
					}
					else if (avp_length > 10)
					{
						l2tp_msg->cdn.r_code.error_present= true;
						l2tp_msg->cdn.r_code.error = be16toh(
								*(uint16_t * ) avp_offset);
						avp_offset += 2;
						l2tp_msg->cdn.r_code.error_massage_present = true;
						l2tp_msg->cdn.r_code.length = avp_length - 10;
						memcpy(l2tp_msg->cdn.r_code.error_massage, avp_offset,
								l2tp_msg->cdn.r_code.length); // check max
					}
				}
				else
				{
					log_error("AVP(Result code) parsing error!");
					return -1;
				}
				break;
			}
			case PROTOCOL_VERSION: // Protocol Version (SCCRP, SCCRQ)
			{
				uint16_t version = be16toh(*(uint16_t * ) (avp_offset));
				if (version != 0x0100) // Only Ver 1,  Rev 0 supported
				{
					log_error("Bad protocol version %04X", version);
					return -1;
				}
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.p_ver.ver = 1;
					l2tp_msg->sccrp.p_ver.rev = 0;
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.p_ver.ver = 1;
					l2tp_msg->sccrq.p_ver.rev = 0;
				}
				else
				{
					log_error("AVP(Protocol Version) parsing error!");
					return -1;
				}
				break;
			}
			case FRAMING_CAPABILITIES: // Framing Capabilities (SCCRP, SCCRQ)
			{
				bool asynchronous = *(avp_offset + 3) & 0x02;
				bool synchronous = *(avp_offset + 3) & 0x01;
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.f_cap.synchronous = synchronous;
					l2tp_msg->sccrp.f_cap.asynchronous = asynchronous;
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.f_cap.synchronous = synchronous;
					l2tp_msg->sccrq.f_cap.asynchronous = asynchronous;
				}
				else
				{
					log_error("AVP(Framing Capabilities) parsing error!");
					return -1;
				}
				break;
			}
			case BEARER_CAPABILITIES: // Bearer Capabilities (SCCRP, SCCRQ)
			{
				bool analog = *(avp_offset + 3) & 0x02;
				bool digital = *(avp_offset + 3) & 0x01;
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.b_cap_present = true;
					l2tp_msg->sccrp.b_cap.analog = analog;
					l2tp_msg->sccrp.b_cap.digital = digital;
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.b_cap_present = true;
					l2tp_msg->sccrq.b_cap.analog = analog;
					l2tp_msg->sccrq.b_cap.digital = digital;
				}
				else
				{
					log_error("AVP(Bearer Capabilities) parsing error!");
					return -1;
				}
				break;
			}
			case TIE_BREAKER: // Tie Breaker (SCCRQ)
			{
				if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.tie_present = true;
					l2tp_msg->sccrq.tie = be64toh(*(uint64_t * ) (avp_offset));
				}
				else
				{
					log_error("AVP(Tie Breaker) parsing error!");
					return -1;
				}
				break;
			}
			case FIRMWARE_REVISION: // Firmware Revision (SCCRP, SCCRQ)
			{
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.f_rev_present = true;
					l2tp_msg->sccrp.f_rev = be16toh(
							*(uint16_t * ) (avp_offset));
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.f_rev_present = true;
					l2tp_msg->sccrq.f_rev = be16toh(
							*(uint16_t * ) (avp_offset));
				}
				else
				{
					log_error("AVP(Firmware Revision) parsing error!");
					return -1;
				}
				break;
			}
			case HOST_NAME: // Host Name (SCCRP, SCCRQ)
			{
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.h_name.length = avp_length - 6;
					memcpy(l2tp_msg->sccrp.h_name.value, avp_offset,
							l2tp_msg->sccrp.h_name.length); // check max
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.h_name.length = avp_length - 6;
					memcpy(l2tp_msg->sccrq.h_name.value, avp_offset,
							l2tp_msg->sccrq.h_name.length); // check max
				}
				else
				{
					log_error("AVP(Host Name) parsing error!");
					return -1;
				}
				break;
			}
			case VENDOR_NAME: // Vendor Name (SCCRP, SCCRQ)
			{
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.v_name_present = true;
					l2tp_msg->sccrp.v_name.length = avp_length - 6;
					memcpy(l2tp_msg->sccrp.v_name.value, avp_offset,
							l2tp_msg->sccrp.v_name.length); // check max
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.v_name_present = true;
					l2tp_msg->sccrq.v_name.length = avp_length - 6;
					memcpy(l2tp_msg->sccrq.v_name.value, avp_offset,
							l2tp_msg->sccrq.v_name.length); // check max
				}
				else
				{
					log_error("AVP(Vendor Name) parsing error!");
					return -1;
				}
				break;
			}
			case ASSIGNED_TUNNEL_ID: // Assigned Tunnel ID (SCCRP, SCCRQ, StopCCN)
			{
				uint16_t remote_tunnel = be16toh(*(uint16_t * ) (avp_offset));
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.tunnel_id = remote_tunnel;
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.tunnel_id = remote_tunnel;
				}
				else if (message_type == StopCCN)
				{
					l2tp_msg->stopccn.tunnel_id = remote_tunnel;
				}
				else
				{
					log_error("AVP(Assigned Tunnel ID) parsing error!");
					return -1;
				}
				break;
			}
			case RECEIVE_WINDOW_SIZE: // Receive Window Size (SCCRQ, SCCRP)
			{
				uint16_t window = be16toh(*(uint16_t * ) (avp_offset));
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.window_present = true;
					l2tp_msg->sccrp.window = window;
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.window_present = true;
					l2tp_msg->sccrq.window = window;
				}
				else
				{
					log_error("AVP(Receive Window Size) parsing error!");
					return -1;
				}
				break;
			}
			case CHALLENGE: // Challenge (SCCRP, SCCRQ)
			{
				if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.challenge_present = true;
					l2tp_msg->sccrp.chal.length = avp_length - 6;
					memcpy(l2tp_msg->sccrp.chal.value, avp_offset,
							l2tp_msg->sccrp.chal.length); // check max
				}
				else if (message_type == SCCRQ)
				{
					l2tp_msg->sccrq.challenge_present = true;
					l2tp_msg->sccrq.chal.length = avp_length - 6;
					memcpy(l2tp_msg->sccrq.chal.value, avp_offset,
							l2tp_msg->sccrq.chal.length); // check max
				}
				else
				{
					log_error("AVP(Challenge) parsing error!");
					return -1;
				}
				break;
			}
			case Q931_CAUSE_CODE: // Q.931 Cause Code (CDN)
			{
				if (message_type == CDN)
				{
					l2tp_msg->cdn.cause_code_preset = true;
					l2tp_msg->cdn.c_code.c_code = be16toh(
							*(uint16_t * ) (avp_offset));
					avp_offset += 2;
					l2tp_msg->cdn.c_code.msg_code = *avp_offset;
					avp_offset++;
					l2tp_msg->cdn.c_code.length = avp_length - 9;
					memcpy(l2tp_msg->cdn.c_code.message, avp_offset,
							l2tp_msg->cdn.c_code.length); // check max
				}
				else
				{
					log_error("AVP(Q.931 Cause Code) parsing error!");
					return -1;
				}
				break;
			}
			case CHALLENGE_RESPONSE: // Challenge Response (SCCCN, SCCRP)
			{
				if (message_type == SCCCN)
				{
					l2tp_msg->scccn.c_resp_present = true;
					memcpy(l2tp_msg->scccn.chal_resp.value, avp_offset, 16);
				}
				else if (message_type == SCCRP)
				{
					l2tp_msg->sccrp.c_resp_present = true;
					memcpy(l2tp_msg->sccrp.chal_resp.value, avp_offset, 16);
				}
				else
				{
					log_error("AVP(Challenge Response) parsing error!");
					return -1;
				}
				break;
			}
			case ASSIGNED_SESSION_ID: // Assigned Session ID (CDN, ICRP, ICRQ, OCRP, OCRQ)
			{
				uint16_t session = be16toh(*(uint16_t * ) avp_offset);
				if (message_type == CDN)
				{
					l2tp_msg->cdn.session_id = session;
				}
				else if (message_type == ICRP)
				{
					l2tp_msg->icrp.session_id = session;
				}
				else if (message_type == ICRQ)
				{
					l2tp_msg->icrq.session_id = session;
				}
				else if (message_type == OCRP)
				{
					l2tp_msg->ocrp.session_id = session;
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.session_id = session;
				}
				else
				{
					log_error("AVP(Assigned Session ID) parsing error!");
					return -1;
				}
				break;
			}
			case CALL_SERIAL_NUMBER: // Call Serial Number (ICRQ, OCRQ)
			{
				uint32_t serial = be32toh(*(uint32_t * ) avp_offset);
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.s_number = serial;
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.s_number = serial;
				}
				else
				{
					log_error("AVP(Call Serial Number) parsing error!");
					return -1;
				}
				break;
			}
			case MINIMUM_BPS: // Minimum BPS (OCRQ)
			{
				if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.min_bps = be32toh(*(uint32_t * ) avp_offset);
				}
				else
				{
					log_error("AVP(Minimum BPS) parsing error!");
					return -1;
				}
				break;
			}
			case MAXIMUM_BPS: // Maximum BPS (OCRQ)
			{

				if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.max_bps = be32toh(*(uint32_t * ) avp_offset);
				}
				else
				{
					log_error("AVP(Maximum BPS) parsing error!");
					return -1;
				}
				break;
			}
			case BEARER_TYPE: // Bearer Type (ICRQ, OCRQ)
			{
				bool analog = *(avp_offset + 3) & 0x02;
				bool digital = *(avp_offset + 3) & 0x01;
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.bearer_type_present = true;
					l2tp_msg->icrq.b_type.analog = analog;
					l2tp_msg->icrq.b_type.digital = digital;
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.b_type.analog = analog;
					l2tp_msg->ocrq.b_type.digital = digital;
				}
				else
				{
					log_error("AVP(Bearer Type) parsing error!");
					return -1;
				}
				break;
			}
			case FRAMING_TYPE: // Framing Type (ICCN, OCCN, OCRQ)
			{
				bool synchronous = *(avp_offset + 3) & 0x01;
				bool asynchronous = *(avp_offset + 3) & 0x02;
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.f_type.asynchronous = asynchronous;
					l2tp_msg->iccn.f_type.synchronous = synchronous;
				}
				else if (message_type == OCCN)
				{
					l2tp_msg->occn.f_type.asynchronous = asynchronous;
					l2tp_msg->occn.f_type.synchronous = synchronous;
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.f_type.asynchronous = asynchronous;
					l2tp_msg->ocrq.f_type.synchronous = synchronous;
				}
				else
				{
					log_error("AVP(Framing Type) parsing error!");
					return -1;
				}
				break;
			}
			case RESERVED_20: // 20 reserved
			{
				log_debug("reserved AVP, ignoring");
				break;
			}
			case CALLED_NUMBER: // Called Number (ICRQ, OCRQ)
			{
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.called_number_present = true;
					l2tp_msg->icrq.called_number.length = avp_length - 6;
					memcpy(l2tp_msg->icrq.called_number.value, avp_offset,
							l2tp_msg->icrq.called_number.length); // check max
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.called_number.length = avp_length - 6;
					memcpy(l2tp_msg->ocrq.called_number.value, avp_offset,
							l2tp_msg->ocrq.called_number.length); // check max
				}
				else
				{
					log_error("AVP(Called Number) parsing error!");
					return -1;
				}
				break;
			}
			case CALLING_NUMBER: // Calling Number (ICRQ)
			{
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.calling_number_present = true;
					l2tp_msg->icrq.calling_number.length = avp_length - 6;
					memcpy(l2tp_msg->icrq.calling_number.value, avp_offset,
							l2tp_msg->icrq.calling_number.length);
				}
				else
				{
					log_error("AVP(Calling Number) parsing error!");
					return -1;
				}
				break;
			}
			case SUB_ADDRESS: // Sub-Address (ICRQ, OCRQ)
			{
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.sub_address_present = true;
					l2tp_msg->icrq.address.length = avp_length - 6;
					memcpy(l2tp_msg->icrq.address.value, avp_offset,
							l2tp_msg->icrq.address.length); // check max
				}
				else if (message_type == OCRQ)
				{
					l2tp_msg->ocrq.sub_address_present = true;
					l2tp_msg->ocrq.address.length = avp_length - 6;
					memcpy(l2tp_msg->ocrq.address.value, avp_offset,
							l2tp_msg->ocrq.address.length); // check max
				}
				else
				{
					log_error("AVP(Sub-Address) parsing error!");
					return -1;
				}
				break;
			}
			case TX_CONNECT_SPEED: // (Tx) Connect Speed (ICCN, OCCN)
			{
				uint32_t speed = be32toh(*(uint32_t * )avp_offset);
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.tx = speed;
				}
				else if (message_type == OCCN)
				{
					l2tp_msg->occn.tx = speed;
				}
				else
				{
					log_error("AVP((Tx) Connect Speed) parsing error!");
					return -1;
				}
				break;
			}
			case PHYSCAL_CHANNEL_ID: // Physical Channel ID (ICRQ, OCRP)
			{
				uint32_t channel = be32toh(*(uint32_t * )avp_offset);
				if (message_type == ICRQ)
				{
					l2tp_msg->icrq.physical_channel_present = true;
					l2tp_msg->icrq.channel_id = channel;
				}
				else if (message_type == OCRP)
				{
					l2tp_msg->ocrp.physical_channel_present = true;
					l2tp_msg->ocrp.channel_id = channel;
				}
				else
				{
					log_error("AVP(Physical Channel ID) parsing error!");
					return -1;
				}
				break;
			}
			case INITIAL_RECEIVED_LCP_CONFREQ: // Initial Received LCP CONFREQ (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.initial_lcp_confreq_present = true;
					l2tp_msg->iccn.initial_lcp_confreq.length = avp_length - 6;
					memcpy(l2tp_msg->iccn.initial_lcp_confreq.value, avp_offset,
							l2tp_msg->iccn.initial_lcp_confreq.length); // check max
				}
				else
				{
					log_error(
							"AVP(Initial Received LCP CONFREQ) parsing error!");
					return -1;
				}
				break;
			}
			case LAST_SENT_LCP_CONFREQ: // Last Sent LCP CONFREQ (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.last_sent_lcp_confreq_present = true;
					l2tp_msg->iccn.last_sent_lcp_confreq.length = avp_length
							- 6;
					memcpy(l2tp_msg->iccn.last_sent_lcp_confreq.value,
							avp_offset,
							l2tp_msg->iccn.last_sent_lcp_confreq.length); // check max
				}
				else
				{
					log_error("AVP(Last Sent LCP CONFREQ) parsing error!");
					return -1;
				}
				break;
			}
			case LAST_RECEIVED_LCP_CONFREQ: // Last Received LCP CONFREQ (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.last_received_lcp_confreq_present = true;
					l2tp_msg->iccn.last_received_lcp_confreq.length = avp_length
							- 6;
					memcpy(l2tp_msg->iccn.last_received_lcp_confreq.value,
							avp_offset,
							l2tp_msg->iccn.last_received_lcp_confreq.length);
				}
				else
				{
					log_error("AVP(Last Received LCP CONFREQ) parsing error!");
					return -1;
				}
				break;
			}
			case PROXY_AUTHEN_TYPE: // Proxy Authen Type (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.authen_type_present = true;
					l2tp_msg->iccn.authen_type = be16toh(
							*(uint16_t * )avp_offset);
				}
				else
				{
					log_error("AVP(Proxy Authen Type) parsing error!");
					return -1;
				}
				break;
			}
			case PROXY_AUTHEN_NAME: // Proxy Authen Name (ICCN)
			{

				if (message_type == ICCN)
				{
					l2tp_msg->iccn.authen_name_present = true;
					l2tp_msg->iccn.authen_name.length = avp_length - 6;
					memcpy(l2tp_msg->iccn.authen_name.value, avp_offset,
							l2tp_msg->iccn.authen_name.length); //check max
				}
				else
				{
					log_error("AVP(Proxy Authen Name) parsing error!");
					return -1;
				}
				break;
			}
			case PROXY_AUTHEN_CHALLENGE: // Proxy Authen Challenge (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.authen_challenge_present = true;
					l2tp_msg->iccn.authen_challenge.length = avp_length - 6;
					memcpy(l2tp_msg->iccn.authen_challenge.value, avp_offset,
							l2tp_msg->iccn.authen_challenge.length);
				}
				else
				{
					log_error("AVP(Proxy Authen Challenge) parsing error!");
					return -1;
				}
				break;
			}
			case PROXY_AUTHEN_ID: // Proxy Authen ID (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.authen_id_present = true;
					l2tp_msg->iccn.authen_id = be16toh(*(uint16_t * )avp_offset)
							& 0x00ff;
				}
				else
				{
					log_error("AVP(Proxy Authen ID) parsing error!");
					return -1;
				}
				break;
			}
			case PROXY_AUTHEN_RESPONSE: // Proxy Authen Response (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.authen_response_present = true;
					l2tp_msg->iccn.authen_response.length = avp_length - 6;
					memcpy(l2tp_msg->iccn.authen_response.value, avp_offset,
							l2tp_msg->iccn.authen_response.length); // check max
				}
				else
				{
					log_error("AVP(Proxy Authen Response) parsing error!");
					return -1;
				}
				break;
			}
			case CALL_ERRORS: // Call Errors (WEN)
			{
				if (message_type == WEN)
				{
					avp_offset += 2;
					l2tp_msg->wen.c_errors.crc_errors = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->wen.c_errors.framing_errors = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->wen.c_errors.hardware_overruns = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->wen.c_errors.buffer_overruns = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->wen.c_errors.timeout_errors = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->wen.c_errors.alignment_errors = be32toh(
							*(uint32_t * )avp_offset);

				}
				else
				{
					log_error("AVP(Call Errors) parsing error!");
					return -1;
				}
				break;
			}
			case ACCM: // ACCM (SLI)
			{
				if (message_type == SLI)
				{
					l2tp_msg->sli.accm.reserved = 0;
					avp_offset += 2;
					l2tp_msg->sli.accm.send_accm = be32toh(
							*(uint32_t * )avp_offset);
					avp_offset += 4;
					l2tp_msg->sli.accm.rcv_accm = be32toh(
							*(uint32_t * )avp_offset);
				}
				else
				{
					log_error("AVP(ACCM) parsing error!");
					return -1;
				}
				break;
			}
			case RANDOM_VECTOR: // Random Vector (All Messages)
			{
				r_vector.length = avp_length - 6;
				r_vector.value = avp_offset;
				log_debug("Random Vector received.Enabled AVP Hiding.");
				break;
			}
			case PRIVATE_GROUP_ID: // Private Group ID (ICCN)
			{
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.group_id_present = true;
					l2tp_msg->iccn.group_id.length = avp_length - 6;
					memcpy(l2tp_msg->iccn.group_id.value, avp_offset,
							l2tp_msg->iccn.group_id.length);
				}
				else
				{
					log_error("AVP(Private Group ID) parsing error!");
					return -1;
				}
				break;
			}
			case RX_CONNECT_SPEED: // (Rx) Connect Speed (ICCN, OCCN)
			{
				uint32_t speed = be32toh(*(uint32_t * )avp_offset);
				if (message_type == ICCN)
				{
					l2tp_msg->iccn.rx_speed_present = true;
					l2tp_msg->iccn.rx = speed;
				}
				else if (message_type == OCCN)
				{
					l2tp_msg->occn.rx_speed_present = true;
					l2tp_msg->occn.rx = speed;
				}
				else
				{
					log_error("AVP((Rx) Connect Speed) parsing error!");
					return -1;
				}
				break;
			}
			case SEQUENCING_REQUIRED: // Sequencing Required (ICCN, OCCN)
			{
				if (message_type == ICCN)
				{

					l2tp_msg->iccn.sequencing_present = true;
				}
				else if (message_type == OCCN)
				{
					l2tp_msg->occn.sequencing_present = true;
				}
				else
				{
					log_error("AVP(Sequencing Required) parsing error!");
					return -1;
				}
				break;
			}
			default:
			{
				//to do
				log_error("Unknown AVP type %u", avp_type);
				continue;
			}

			}

			// next AVP
			p_offset += avp_length;
			avps_length -= avp_length;
		}

	}
	else
	{
		log_error("Type(T) bit MUST be set to 1 for control message");
		return -1;
	}
	return 0;
}

int l2tp_control_encode(uint8_t *mbuf, size_t *length,
		const l2tp_control_message *l2tp_msg)
{
	uint8_t *tmp_buf = mbuf;
	uint8_t h_len = 12;
	uint8_t *avp_offset = tmp_buf + h_len;

	*(uint16_t *) (tmp_buf + 0) = htobe16(l2tp_msg->header.type_flags); // flags/ver
	// *(uint16_t *) (tmp_buf + 0) = htobe16(0xC802); // default control message flags
	*(uint16_t *) (tmp_buf + 2) = htobe16(h_len); // length
	*(uint16_t *) (tmp_buf + 4) = htobe16(l2tp_msg->header.tunnel_id); // tunnel
	*(uint16_t *) (tmp_buf + 6) = htobe16(l2tp_msg->header.session_id); // session
	*(uint16_t *) (tmp_buf + 8) = htobe16(l2tp_msg->header.ns); // sequence
	*(uint16_t *) (tmp_buf + 10) = htobe16(l2tp_msg->header.nr); // sequence
	*length = h_len;

	// check ZLB
	if (l2tp_msg->message_type == ZLB)
	{
		return 0;
	}
	// mandatory AVP for all messages
	// add_avp8(avp_offset, MESSAGE_TYPE, &l2tp_msg->message_type, true);
	size_t size = 0;
	size = add_avp_message_type(avp_offset, &l2tp_msg->message_type);
	*length += size;
	avp_offset += size;

	// encode AVPs
	switch (l2tp_msg->message_type)
	{
	case SCCRQ:
	{

		size = add_avp_protocol_version(avp_offset, &l2tp_msg->sccrq.p_ver);
		*length += size;
		avp_offset += size;

		size = add_avp_host_name(avp_offset, &l2tp_msg->sccrq.h_name);
		*length += size;
		avp_offset += size;

		size = add_avp_framing_capabilities(avp_offset, &l2tp_msg->sccrq.f_cap);
		*length += size;
		avp_offset += size;

		size = add_avp_assigned_tunnel_id(avp_offset,
				&l2tp_msg->sccrq.tunnel_id);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->sccrq.b_cap_present)
		{
			size = add_avp_bearer_capabilities(avp_offset,
					&l2tp_msg->sccrq.b_cap);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrq.window_present)
		{
			size = add_avp_receive_window_size(avp_offset,
					&l2tp_msg->sccrq.window);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrq.challenge_present)
		{
			size = add_avp_challenge(avp_offset, &l2tp_msg->sccrq.chal);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrq.tie_present)
		{
			size = add_avp_tie_breaker(avp_offset, &l2tp_msg->sccrq.tie);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrq.f_rev_present)
		{
			size = add_avp_firmware_revision(avp_offset,
					&l2tp_msg->sccrq.f_rev);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrq.v_name_present)
		{
			size = add_avp_vendor_name(avp_offset, &l2tp_msg->sccrq.v_name);
			*length += size;
			avp_offset += size;
		}

		break;
	}
	case SCCRP:
	{
		size = add_avp_protocol_version(avp_offset, &l2tp_msg->sccrp.p_ver);
		*length += size;
		avp_offset += size;

		size = add_avp_framing_capabilities(avp_offset, &l2tp_msg->sccrp.f_cap);
		*length += size;
		avp_offset += size;

		size = add_avp_host_name(avp_offset, &l2tp_msg->sccrp.h_name);
		*length += size;
		avp_offset += size;

		size = add_avp_assigned_tunnel_id(avp_offset,
				&l2tp_msg->sccrp.tunnel_id);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->sccrq.b_cap_present)
		{
			size = add_avp_bearer_capabilities(avp_offset,
					&l2tp_msg->sccrp.b_cap);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrp.f_rev_present)
		{
			size = add_avp_firmware_revision(avp_offset,
					&l2tp_msg->sccrp.f_rev);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrp.v_name_present)
		{
			size = add_avp_vendor_name(avp_offset, &l2tp_msg->sccrp.v_name);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrp.window_present)
		{
			size = add_avp_receive_window_size(avp_offset,
					&l2tp_msg->sccrp.window);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrp.challenge_present)
		{
			size = add_avp_challenge(avp_offset, &l2tp_msg->sccrp.chal);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->sccrp.c_resp_present)
		{
			size = add_avp_challenge_response(avp_offset,
					&l2tp_msg->sccrp.chal_resp);
			*length += size;
			avp_offset += size;
		}

		break;
	}
	case SCCCN:
	{
		if (l2tp_msg->scccn.c_resp_present)
		{
			size = add_avp_challenge_response(avp_offset,
					&l2tp_msg->scccn.chal_resp);
			*length += size;
		}
		break;
	}
	case StopCCN:
	{
		size = add_avp_assigned_tunnel_id(avp_offset,
				&l2tp_msg->stopccn.tunnel_id);
		*length += size;
		avp_offset += size;

		size = add_avp_result_code(avp_offset, &l2tp_msg->stopccn.r_code);
		*length += size;
		break;
	}
	case HELLO:
	{
		break;
	}
	case ICRQ:
	{
		size = add_avp_assigned_session_id(avp_offset,
				&l2tp_msg->icrq.session_id);
		*length += size;
		avp_offset += size;

		size = add_avp_call_serial_number(avp_offset, &l2tp_msg->icrq.s_number);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->icrq.bearer_type_present)
		{
			size = add_avp_bearer_type(avp_offset, &l2tp_msg->icrq.b_type);
			*length += size;
			avp_offset += size;
		}

		if (l2tp_msg->icrq.physical_channel_present)
		{
			size = add_avp_physical_channel_id(avp_offset,
					&l2tp_msg->icrq.channel_id);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->icrq.calling_number_present)
		{
			size = add_avp_calling_number(avp_offset,
					&l2tp_msg->icrq.calling_number);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->icrq.called_number_present)
		{
			size = add_avp_called_number(avp_offset,
					&l2tp_msg->icrq.called_number);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->icrq.sub_address_present)
		{
			size = add_avp_sub_address(avp_offset, &l2tp_msg->icrq.address);
			*length += size;
		}

		break;
	}
	case ICRP:
	{
		size = add_avp_assigned_session_id(avp_offset,
				&l2tp_msg->icrp.session_id);
		*length += size;
		break;
	}
	case ICCN:
	{
		size = add_avp_tx_connect_speed(avp_offset, &l2tp_msg->iccn.tx);
		*length += size;
		avp_offset += size;

		size = add_avp_framing_type(avp_offset, &l2tp_msg->iccn.f_type);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->iccn.initial_lcp_confreq_present)
		{
			size = add_avp_initial_received_lcp_confreq(avp_offset,
					&l2tp_msg->iccn.initial_lcp_confreq);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.last_sent_lcp_confreq_present)
		{
			size = add_avp_last_sent_lcp_confreq(avp_offset,
					&l2tp_msg->iccn.last_sent_lcp_confreq);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.last_received_lcp_confreq_present)
		{
			size = add_avp_last_received_lcp_confreq(avp_offset,
					&l2tp_msg->iccn.last_received_lcp_confreq);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.authen_type_present)
		{
			size = add_avp_proxy_authen_type(avp_offset,
					&l2tp_msg->iccn.authen_type);
			*length += size;
			avp_offset += size;

		}
		if (l2tp_msg->iccn.authen_name_present)
		{
			size = add_avp_proxy_authen_name(avp_offset,
					&l2tp_msg->iccn.authen_name);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.authen_challenge_present)
		{
			size = add_avp_proxy_authen_challenge(avp_offset,
					&l2tp_msg->iccn.authen_challenge);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.authen_id_present)
		{
			size = add_avp_proxy_authen_id(avp_offset,
					&l2tp_msg->iccn.authen_id);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.authen_response_present)
		{
			size = add_avp_proxy_authen_response(avp_offset,
					&l2tp_msg->iccn.authen_response);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->iccn.group_id_present)
		{
			size = add_avp_private_group_id(avp_offset,
					&l2tp_msg->iccn.group_id);
			*length += size;
			avp_offset += size;

		}
		if (l2tp_msg->iccn.rx_speed_present)
		{
			size = add_avp_rx_connect_speed(avp_offset, &l2tp_msg->iccn.rx);
			*length += size;
			avp_offset += size;

		}
		if (l2tp_msg->iccn.sequencing_present)
		{
			size = add_avp_sequencing_required(avp_offset);
			*length += size;

		}
		break;
	}
	case OCRQ:
	{
		size = add_avp_assigned_session_id(avp_offset,
				&l2tp_msg->ocrq.session_id);
		*length += size;
		avp_offset += size;

		size = add_avp_call_serial_number(avp_offset, &l2tp_msg->ocrq.s_number);
		*length += size;
		avp_offset += size;

		size = add_avp_mimimum_bps(avp_offset, &l2tp_msg->ocrq.min_bps);
		*length += size;
		avp_offset += size;

		size = add_avp_maximum_bps(avp_offset, &l2tp_msg->ocrq.max_bps);
		*length += size;
		avp_offset += size;

		size = add_avp_bearer_type(avp_offset, &l2tp_msg->ocrq.b_type);
		*length += size;
		avp_offset += size;

		size = add_avp_framing_type(avp_offset, &l2tp_msg->ocrq.f_type);
		*length += size;
		avp_offset += size;

		size = add_avp_called_number(avp_offset, &l2tp_msg->ocrq.called_number);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->ocrq.sub_address_present)
		{
			size = add_avp_sub_address(avp_offset, &l2tp_msg->ocrq.address);
			*length += size;
		}

		break;
	}
	case OCRP:
	{
		size = add_avp_assigned_session_id(avp_offset,
				&l2tp_msg->ocrp.session_id);
		*length += size;
		avp_offset += size;
		if (&l2tp_msg->ocrp.physical_channel_present)
		{
			size = add_avp_physical_channel_id(avp_offset,
					&l2tp_msg->ocrp.channel_id);
			*length += size;
		}
		break;
	}
	case OCCN:
	{
		size = add_avp_tx_connect_speed(avp_offset, &l2tp_msg->occn.tx);
		*length += size;
		avp_offset += size;

		size = add_avp_framing_type(avp_offset, &l2tp_msg->occn.f_type);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->occn.rx_speed_present)
		{
			size = add_avp_rx_connect_speed(avp_offset, &l2tp_msg->occn.rx);
			*length += size;
			avp_offset += size;
		}
		if (l2tp_msg->occn.sequencing_present)
		{
			size = add_avp_sequencing_required(avp_offset);
			*length += size;
		}

		break;
	}
	case CDN:
	{
		size = add_avp_result_code(avp_offset, &l2tp_msg->cdn.r_code);
		*length += size;
		avp_offset += size;

		size = add_avp_assigned_session_id(avp_offset,
				&l2tp_msg->cdn.session_id);
		*length += size;
		avp_offset += size;

		if (l2tp_msg->cdn.cause_code_preset)
		{
			size = add_avp_q931_cause_code(avp_offset, &l2tp_msg->cdn.c_code);
			*length += size;
		}

		break;
	}
	case WEN:
	{
		size = add_avp_call_errors(avp_offset, &l2tp_msg->wen.c_errors);
		*length += size;
		break;
	}
	case SLI:
	{
		size = add_avp_accm(avp_offset, &l2tp_msg->sli.accm);
		*length += size;
		break;
	}
	default:
	{
		log_debug("not supported yet %d", l2tp_msg->message_type);
		return -1;
	}

	}

	*(uint16_t *) (tmp_buf + 2) = htobe16(*length); // update length
	return 0;
}

size_t add_avp8(uint8_t *offset, uint16_t avp_type, const void *avp_data,
bool mandatory)
{
	*(uint16_t *) offset = htobe16(mandatory ? 0x8008 : 0x0008);
	offset += 2;
	*(uint16_t *) offset = htobe16(0);
	offset += 2;
	*(uint16_t *) offset = htobe16(avp_type);
	offset += 2;
	*(uint16_t *) offset = htobe16(*(uint16_t * )avp_data);
	return 8;
}

size_t add_avp10(uint8_t *offset, uint16_t avp_type, const void *avp_data,
bool mandatory)
{
	*(uint16_t *) offset = htobe16(mandatory ? 0x800A : 0x000A);
	offset += 2;
	*(uint16_t *) offset = htobe16(0);
	offset += 2;
	*(uint16_t *) offset = htobe16(avp_type);
	offset += 2;
	*(uint32_t *) offset = htobe32(*(uint32_t * )avp_data);
	return 10;
}

size_t add_avp12(uint8_t *offset, uint16_t avp_type, const void *avp_data,
bool mandatory)
{
	*(uint16_t *) offset = htobe16(mandatory ? 0x800C : 0x000C);
	offset += 2;
	*(uint16_t *) offset = htobe16(0);
	offset += 2;
	*(uint16_t *) offset = htobe16(avp_type);
	offset += 2;
	*(uint64_t *) offset = htobe64(*(uint64_t * )avp_data);
	return 12;
}

size_t add_avpX(uint8_t *offset, uint16_t avp_type, const void *avp_data,
		uint16_t avp_length, bool mandatory)
{
	*(uint16_t *) offset = htobe16((mandatory ? 0x8000 : 0) + avp_length + 6);
	offset += 2;
	*(uint16_t *) offset = htobe16(0);
	offset += 2;
	*(uint16_t *) offset = htobe16(avp_type);
	offset += 2;
	memcpy(offset, avp_data, avp_length);
	return avp_length + 6;
}

size_t add_avp_message_type(uint8_t *avp_offset, const uint16_t *message_type)
{
	return add_avp8(avp_offset, MESSAGE_TYPE, message_type, true);
}

size_t add_avp_protocol_version(uint8_t *avp_offset,
		const t_protocol_version *protocol_version)
{
	uint16_t ver_rev = htobe16(*(uint16_t * )protocol_version);
	return add_avp8(avp_offset, PROTOCOL_VERSION, &ver_rev, true);
}

size_t add_avp_host_name(uint8_t *avp_offset, const t_host_name *host_name)
{
	return add_avpX(avp_offset, HOST_NAME, host_name->value, host_name->length,
	true);
}

size_t add_avp_framing_capabilities(uint8_t *avp_offset,
		const t_framing_capabilities *framing_capabilities)
{
	uint32_t cap = framing_capabilities->asynchronous * 2
			+ framing_capabilities->synchronous;
	return add_avp10(avp_offset, FRAMING_CAPABILITIES, &cap, true);
}

size_t add_avp_assigned_tunnel_id(uint8_t *avp_offset,
		const t_assigned_tunnel_id *assigned_tunnel_id)
{
	return add_avp8(avp_offset, ASSIGNED_TUNNEL_ID, assigned_tunnel_id,
	true);
}

size_t add_avp_bearer_capabilities(uint8_t *avp_offset,
		const t_bearer_capabilities *bearer_capabilities)
{

	uint32_t cap = bearer_capabilities->analog * 2
			+ bearer_capabilities->digital;
	return add_avp10(avp_offset, BEARER_CAPABILITIES, &cap, true);
}

size_t add_avp_receive_window_size(uint8_t *avp_offset,
		const t_receive_window_size *receive_window_size)
{
	return add_avp8(avp_offset, RECEIVE_WINDOW_SIZE, receive_window_size,
	true);
}

size_t add_avp_challenge(uint8_t *avp_offset, const t_challenge *challenge)
{
	return add_avpX(avp_offset, CHALLENGE, challenge->value, challenge->length,
	true);
}

size_t add_avp_tie_breaker(uint8_t *avp_offset,
		const t_tie_breaker *tie_breaker)
{
	return add_avp12(avp_offset, TIE_BREAKER, tie_breaker, false);
}

size_t add_avp_firmware_revision(uint8_t *avp_offset,
		const t_firmware_revision *firmware_revision)
{
	return add_avp8(avp_offset, FIRMWARE_REVISION, firmware_revision,
	false);
}

size_t add_avp_vendor_name(uint8_t *avp_offset,
		const t_vendor_name *vendor_name)
{
	return add_avpX(avp_offset, VENDOR_NAME, vendor_name->value,
			vendor_name->length,
			false);
}

size_t add_avp_challenge_response(uint8_t *avp_offset,
		const t_challenge_response *challenge_response)
{
	return add_avpX(avp_offset, CHALLENGE_RESPONSE, challenge_response->value,
			16,
			true);
}

size_t add_avp_result_code(uint8_t *avp_offset,
		const t_result_code *result_code)
{
	uint16_t size = add_avp8(avp_offset, RESULT_CODE, &result_code->code,
	true);
	if (result_code->error_present)
	{
		*(uint16_t *) (avp_offset + size) = htobe16(result_code->error);
		size += 2;
	}
	if (result_code->error_massage_present)
	{
		memcpy(avp_offset + size, result_code->error_massage,
				result_code->length);
		size += result_code->length;
	}

	*(uint16_t *) avp_offset += htobe16(size - 8);
	return size;
}

size_t add_avp_assigned_session_id(uint8_t *avp_offset,
		const t_assigned_session_id *assigned_session_id)
{
	return add_avp8(avp_offset, ASSIGNED_SESSION_ID, assigned_session_id,
	true);
}

size_t add_avp_call_serial_number(uint8_t *avp_offset,
		const t_call_serial_number *call_serial_number)
{
	return add_avp10(avp_offset, CALL_SERIAL_NUMBER, call_serial_number, true);
}

size_t add_avp_bearer_type(uint8_t *avp_offset,
		const t_bearer_type *bearer_type)
{
	uint32_t type = bearer_type->analog * 2 + bearer_type->digital;
	return add_avp10(avp_offset, BEARER_TYPE, &type, true);
}

size_t add_avp_physical_channel_id(uint8_t *avp_offset,
		const t_physical_channel_id *physical_channel_id)
{
	return add_avp10(avp_offset, PHYSCAL_CHANNEL_ID, physical_channel_id, false);
}

size_t add_avp_calling_number(uint8_t *avp_offset,
		const t_calling_number *calling_number)
{
	return add_avpX(avp_offset, CALLING_NUMBER, calling_number->value,
			calling_number->length, true);
}

size_t add_avp_called_number(uint8_t *avp_offset,
		const t_called_number *called_number)
{
	return add_avpX(avp_offset, CALLED_NUMBER, called_number->value,
			called_number->length, true);
}

size_t add_avp_sub_address(uint8_t *avp_offset,
		const t_sub_address *sub_address)
{
	return add_avpX(avp_offset, SUB_ADDRESS, sub_address->value,
			sub_address->length, true);
}
size_t add_avp_tx_connect_speed(uint8_t *avp_offset,
		const t_tx_connect_speed *tx_connect_speed)
{
	return add_avp10(avp_offset, TX_CONNECT_SPEED, tx_connect_speed, true);
}

size_t add_avp_framing_type(uint8_t *avp_offset,
		const t_framing_type *framing_type)
{
	uint32_t type = framing_type->asynchronous * 2 + framing_type->synchronous;
	return add_avp10(avp_offset, FRAMING_TYPE, &type, true);
}

size_t add_avp_initial_received_lcp_confreq(uint8_t *avp_offset,
		const t_initial_received_lcp_confreq *initial_received_lcp_confreq)
{
	return add_avpX(avp_offset, INITIAL_RECEIVED_LCP_CONFREQ,
			initial_received_lcp_confreq->value,
			initial_received_lcp_confreq->length, false);
}

size_t add_avp_last_sent_lcp_confreq(uint8_t *avp_offset,
		const t_last_sent_lcp_confreq *last_sent_lcp_confreq)
{
	return add_avpX(avp_offset, LAST_SENT_LCP_CONFREQ,
			last_sent_lcp_confreq->value, last_sent_lcp_confreq->length, false);
}

size_t add_avp_last_received_lcp_confreq(uint8_t *avp_offset,
		const t_last_received_lcp_confreq *last_received_lcp_confreq)
{
	return add_avpX(avp_offset, LAST_RECEIVED_LCP_CONFREQ,
			last_received_lcp_confreq->value, last_received_lcp_confreq->length,
			false);
}

size_t add_avp_proxy_authen_type(uint8_t *avp_offset,
		const t_proxy_authen_type *proxy_authen_type)
{
	return add_avp8(avp_offset, PROXY_AUTHEN_TYPE, proxy_authen_type, false);
}

size_t add_avp_proxy_authen_name(uint8_t *avp_offset,
		const t_proxy_authen_name * proxy_authen_name)
{
	return add_avpX(avp_offset, PROXY_AUTHEN_NAME, proxy_authen_name->value,
			proxy_authen_name->length, false);
}

size_t add_avp_proxy_authen_challenge(uint8_t *avp_offset,
		const t_proxy_authen_challenge *proxy_authen_challenge)
{
	return add_avpX(avp_offset, PROXY_AUTHEN_CHALLENGE,
			proxy_authen_challenge->value, proxy_authen_challenge->length,
			false);
}

size_t add_avp_proxy_authen_id(uint8_t *avp_offset,
		const t_proxy_authen_id *proxy_authen_id)
{
	return add_avp8(avp_offset, PROXY_AUTHEN_ID, proxy_authen_id, false);
}

size_t add_avp_proxy_authen_response(uint8_t *avp_offset,
		const t_proxy_authen_response * proxy_authen_response)
{
	return add_avpX(avp_offset, PROXY_AUTHEN_RESPONSE,
			proxy_authen_response->value, proxy_authen_response->length, false);
}

size_t add_avp_private_group_id(uint8_t *avp_offset,
		const t_private_group_id *private_group_id)
{
	return add_avpX(avp_offset, PRIVATE_GROUP_ID, private_group_id->value,
			private_group_id->length, false);
}

size_t add_avp_rx_connect_speed(uint8_t *avp_offset,
		const t_rx_connect_speed *rx_connect_speed)
{
	return add_avp10(avp_offset, RX_CONNECT_SPEED, rx_connect_speed, false);
}

size_t add_avp_sequencing_required(uint8_t *avp_offset)
{
	return add_avpX(avp_offset, SEQUENCING_REQUIRED, NULL, 0,
	true);
}

size_t add_avp_mimimum_bps(uint8_t *avp_offset,
		const t_minimum_bps *minimum_bps)
{
	return add_avp10(avp_offset, MINIMUM_BPS, minimum_bps, true);
}

size_t add_avp_maximum_bps(uint8_t *avp_offset,
		const t_maximum_bps *maximum_bps)
{
	return add_avp10(avp_offset, MAXIMUM_BPS, maximum_bps, true);
}

size_t add_avp_q931_cause_code(uint8_t *avp_offset,
		const t_q931_cause_code *q931_cause_code)
{
	uint16_t size = add_avp8(avp_offset, Q931_CAUSE_CODE,
			&q931_cause_code->c_code, true);
	*(avp_offset + size) = q931_cause_code->msg_code;
	size++;
	memcpy(avp_offset + size, q931_cause_code->message,
			q931_cause_code->length);
	size += q931_cause_code->length;
	*(uint16_t *) avp_offset += htobe16(size - 8);
	return size;
}

size_t add_avp_call_errors(uint8_t *avp_offset,
		const t_call_errors *call_errors)
{
	uint16_t size = add_avp8(avp_offset, CALL_ERRORS, &call_errors->reserved,
	true);
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->crc_errors);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->framing_errors);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->hardware_overruns);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->buffer_overruns);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->timeout_errors);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(call_errors->alignment_errors);
	size += 4;
	*(uint16_t *) avp_offset += htobe16(size - 8);
	return size;
}

size_t add_avp_accm(uint8_t *avp_offset, const t_accm * accm)
{
	uint16_t size = add_avp8(avp_offset, ACCM, &accm->reserved,
	true);
	*(uint32_t *) (avp_offset + size) = htobe32(accm->send_accm);
	size += 4;
	*(uint32_t *) (avp_offset + size) = htobe32(accm->rcv_accm);
	size += 4;
	*(uint16_t *) avp_offset += htobe16(size - 8);
	return size;
}
