/*
 * parser.h
 *
 *  Created on: Feb 18, 2018
 *      Author: cicerali
 */

#ifndef PARSER_H_
#define PARSER_H_

#define _BSD_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <stdbool.h>
#include <log.h>

/*
 Control Connection Management

 0  (reserved)

 1  (SCCRQ)    Start-Control-Connection-Request
 2  (SCCRP)    Start-Control-Connection-Reply
 3  (SCCCN)    Start-Control-Connection-Connected
 4  (StopCCN)  Stop-Control-Connection-Notification
 5  (reserved)
 6  (HELLO)    Hello

 Call Management

 7  (OCRQ)     Outgoing-Call-Request
 8  (OCRP)     Outgoing-Call-Reply
 9  (OCCN)     Outgoing-Call-Connected
 10 (ICRQ)     Incoming-Call-Request
 11 (ICRP)     Incoming-Call-Reply
 12 (ICCN)     Incoming-Call-Connected
 13 (reserved)
 14 (CDN)      Call-Disconnect-Notify

 Error Reporting

 15 (WEN)      WAN-Error-Notify

 PPP Session Control

 16 (SLI)      Set-Link-Info
 */

enum CONTROL_MESSAGE_TYPES
{
	RESERVED_0 = 0,
	SCCRQ,
	SCCRP,
	SCCCN,
	StopCCN,
	RESERVED_5,
	HELLO,
	OCRQ,
	OCRP,
	OCCN,
	ICRQ,
	ICRP,
	ICCN,
	RESERVED_13,
	CDN,
	WEN,
	SLI,
	ZLB = UINT16_MAX
};

enum AVP_TYPES
{
	MESSAGE_TYPE = 0,
	RESULT_CODE,
	PROTOCOL_VERSION,
	FRAMING_CAPABILITIES,
	BEARER_CAPABILITIES,
	TIE_BREAKER,
	FIRMWARE_REVISION,
	HOST_NAME,
	VENDOR_NAME,
	ASSIGNED_TUNNEL_ID,
	RECEIVE_WINDOW_SIZE,
	CHALLENGE,
	Q931_CAUSE_CODE,
	CHALLENGE_RESPONSE,
	ASSIGNED_SESSION_ID,
	CALL_SERIAL_NUMBER,
	MINIMUM_BPS,
	MAXIMUM_BPS,
	BEARER_TYPE,
	FRAMING_TYPE,
	RESERVED_20,
	CALLED_NUMBER,
	CALLING_NUMBER,
	SUB_ADDRESS,
	TX_CONNECT_SPEED,
	PHYSCAL_CHANNEL_ID,
	INITIAL_RECEIVED_LCP_CONFREQ,
	LAST_SENT_LCP_CONFREQ,
	LAST_RECEIVED_LCP_CONFREQ,
	PROXY_AUTHEN_TYPE,
	PROXY_AUTHEN_NAME,
	PROXY_AUTHEN_CHALLENGE,
	PROXY_AUTHEN_ID,
	PROXY_AUTHEN_RESPONSE,
	CALL_ERRORS,
	ACCM,
	RANDOM_VECTOR,
	PRIVATE_GROUP_ID,
	RX_CONNECT_SPEED,
	SEQUENCING_REQUIRED
};

typedef struct l2tp_header
{
	uint16_t type_flags;
	uint16_t tunnel_id;
	uint16_t session_id;
	uint16_t ns;
	uint16_t nr;
} l2tp_header;

typedef struct t_random_vector
{
	uint16_t length;
	const uint8_t *value;
} t_random_vector;

typedef struct t_protocol_version
{
	uint8_t ver;
	uint8_t rev;
} t_protocol_version;

typedef struct t_host_name
{
	uint16_t length;
	char value[128];
} t_host_name;

typedef struct t_framing_capabilities
{
	bool synchronous;bool asynchronous;
} t_framing_capabilities;

typedef uint16_t t_assigned_tunnel_id;

typedef struct t_bearer_capabilities
{
	bool digital;bool analog;
} t_bearer_capabilities;

typedef uint16_t t_receive_window_size;

typedef struct t_challenge
{
	uint16_t length;
	char value[128];
} t_challenge;

typedef uint64_t t_tie_breaker;

typedef uint16_t t_firmware_revision;

typedef struct t_vendor_name
{
	uint16_t length;
	char value[128];
} t_vendor_name;

typedef struct t_challenge_response
{
	char value[16];
} t_challenge_response;

typedef struct t_result_code
{
	uint16_t length;
	uint16_t code;bool error_present;
	uint16_t error;bool error_massage_present;
	char error_massage[128];
} t_result_code;

typedef uint16_t t_assigned_session_id;

typedef uint32_t t_call_serial_number;

typedef uint32_t t_minimum_bps;
typedef uint32_t t_maximum_bps;

typedef struct t_bearer_type
{
	bool analog;bool digital;
} t_bearer_type;

typedef struct t_framing_type
{
	bool synchronous;bool asynchronous;
} t_framing_type;

typedef struct t_called_number
{
	uint16_t length;
	char value[128];
} t_called_number;

typedef t_called_number t_calling_number;

typedef struct t_sub_address
{
	uint16_t length;
	char value[128];
} t_sub_address;

typedef uint32_t t_physical_channel_id;

typedef uint32_t t_tx_connect_speed;
typedef uint32_t t_rx_connect_speed;

typedef struct t_initial_received_lcp_confreq
{
	uint16_t length;
	char value[128];
} t_initial_received_lcp_confreq;

typedef t_initial_received_lcp_confreq t_last_sent_lcp_confreq;
typedef t_initial_received_lcp_confreq t_last_received_lcp_confreq;

typedef uint16_t t_proxy_authen_type;

typedef struct t_proxy_authen_name
{
	uint16_t length;
	char value[128];
} t_proxy_authen_name;

typedef struct t_proxy_authen_challenge
{
	uint16_t length;
	char value[128];
} t_proxy_authen_challenge;

typedef uint16_t t_proxy_authen_id;

typedef struct t_proxy_authen_response
{
	uint16_t length;
	char value[128];
} t_proxy_authen_response;

typedef struct t_private_group_id
{
	uint16_t length;
	char value[128];
} t_private_group_id;

typedef struct t_q931_cause_code
{
	uint16_t c_code;
	uint8_t msg_code;
	uint16_t length;
	char message[128];
} t_q931_cause_code;

typedef struct t_call_errors
{
	uint16_t reserved;
	uint32_t crc_errors;
	uint32_t framing_errors;
	uint32_t hardware_overruns;
	uint32_t buffer_overruns;
	uint32_t timeout_errors;
	uint32_t alignment_errors;
} t_call_errors;

typedef struct t_accm
{
	uint16_t reserved;
	uint32_t send_accm;
	uint32_t rcv_accm;
} t_accm;

typedef struct t_sccrq
{
	// mandotary AVPs
	t_protocol_version p_ver;
	t_host_name h_name;
	t_framing_capabilities f_cap;
	t_assigned_tunnel_id tunnel_id;

	// optional AVPs
	bool b_cap_present;
	t_bearer_capabilities b_cap;bool window_present;
	t_receive_window_size window;bool challenge_present;
	t_challenge chal;bool tie_present;
	t_tie_breaker tie;bool f_rev_present;
	t_firmware_revision f_rev;bool v_name_present;
	t_vendor_name v_name;
} t_sccrq;

typedef struct t_sccrp
{
	// mandotary AVPs
	t_protocol_version p_ver;
	t_host_name h_name;
	t_framing_capabilities f_cap;
	t_assigned_tunnel_id tunnel_id;

	// optional AVPs
	bool b_cap_present;
	t_bearer_capabilities b_cap;bool window_present;
	t_receive_window_size window;bool challenge_present;
	t_challenge chal;bool c_resp_present;
	t_challenge_response chal_resp;bool f_rev_present;
	t_firmware_revision f_rev;bool v_name_present;
	t_vendor_name v_name;

} t_sccrp;

typedef struct t_scccn
{
	// optional AVP
	bool c_resp_present;
	t_challenge_response chal_resp;
} t_scccn;

typedef struct t_stopccn
{
	// mandotary AVPs
	t_assigned_tunnel_id tunnel_id;
	t_result_code r_code;
} t_stopccn;

typedef struct t_ocrq
{
	// mandotary AVPs
	t_assigned_session_id session_id;
	t_call_serial_number s_number;
	t_minimum_bps min_bps;
	t_maximum_bps max_bps;
	t_bearer_type b_type;
	t_framing_type f_type;
	t_called_number called_number;

	// optional AVP
	bool sub_address_present;
	t_sub_address address;

} t_ocrq;

typedef struct t_ocrp
{
	// mandotary AVP
	t_assigned_session_id session_id;

	// optional AVP
	bool physical_channel_present;
	t_physical_channel_id channel_id;
} t_ocrp;

typedef struct t_occn
{
	// mandotary AVPs
	t_tx_connect_speed tx;
	t_framing_type f_type;

	// optional AVPs
	bool rx_speed_present;
	t_rx_connect_speed rx;bool sequencing_present;
} t_occn;

typedef struct t_icrq
{
	// mandotary AVPs
	t_assigned_session_id session_id;
	t_call_serial_number s_number;

	// optional AVPs
	bool bearer_type_present;
	t_bearer_type b_type;bool physical_channel_present;
	t_physical_channel_id channel_id;bool calling_number_present;
	t_calling_number calling_number;bool called_number_present;
	t_called_number called_number;bool sub_address_present;
	t_sub_address address;

} t_icrq;

typedef struct t_icrp
{
	// mandotary AVP
	t_assigned_session_id session_id;
} t_icrp;

typedef struct t_iccn
{
	// mandotary AVPs
	t_tx_connect_speed tx;
	t_framing_type f_type;

	// optional AVPs
	bool initial_lcp_confreq_present;
	t_initial_received_lcp_confreq initial_lcp_confreq;bool last_sent_lcp_confreq_present;
	t_last_sent_lcp_confreq last_sent_lcp_confreq;bool last_received_lcp_confreq_present;
	t_last_received_lcp_confreq last_received_lcp_confreq;bool authen_type_present;
	t_proxy_authen_type authen_type;bool authen_name_present;
	t_proxy_authen_name authen_name;bool authen_challenge_present;
	t_proxy_authen_challenge authen_challenge;bool authen_id_present;
	t_proxy_authen_id authen_id;bool authen_response_present;
	t_proxy_authen_response authen_response;bool group_id_present;
	t_private_group_id group_id;bool rx_speed_present;
	t_rx_connect_speed rx;bool sequencing_present;
} t_iccn;

typedef struct t_cdn
{
	// mandotary AVP
	t_assigned_session_id session_id;
	t_result_code r_code;

	// optional AVPs
	bool cause_code_preset;
	t_q931_cause_code c_code;
} t_cdn;

typedef struct t_wen
{
	t_call_errors c_errors;
} t_wen;

typedef struct t_sli
{
	t_accm accm;
} t_sli;

typedef struct l2tp_control_message
{
	l2tp_header header;
	uint16_t message_type;
	union
	{
		t_sccrq sccrq;
		t_sccrp sccrp;
		t_scccn scccn;
		t_stopccn stopccn;
		t_ocrq ocrq;
		t_ocrp ocrp;
		t_occn occn;
		t_icrq icrq;
		t_icrp icrp;
		t_iccn iccn;
		t_cdn cdn;
		t_wen wen;
		t_sli sli;
	};
} l2tp_control_message;

int l2tp_control_encode(uint8_t *mbuf, size_t *length,
		const l2tp_control_message *l2tp_msg);
int l2tp_control_decode(const uint8_t *mbuf, const size_t length,
		l2tp_control_message *l2tp_msg);
size_t add_avp8(uint8_t *offset, uint16_t avp_type, const void *avp_data,
bool mandatory);
size_t add_avpX(uint8_t *offset, uint16_t avp_type, const void *avp_data,
		uint16_t avp_length, bool mandatory);
size_t add_avp_message_type(uint8_t *avp_offset, const uint16_t *message_type);
size_t add_avp_protocol_version(uint8_t *avp_offset,
		const t_protocol_version *protocol_version);
size_t add_avp_host_name(uint8_t *avp_offset, const t_host_name *host_name);
size_t add_avp_framing_capabilities(uint8_t *avp_offset,
		const t_framing_capabilities *framing_capabilities);
size_t add_avp_assigned_tunnel_id(uint8_t *avp_offset,
		const t_assigned_tunnel_id *assigned_tunnel_id);
size_t add_avp_bearer_capabilities(uint8_t *avp_offset,
		const t_bearer_capabilities *bearer_capabilities);
size_t add_avp_receive_window_size(uint8_t *avp_offset,
		const t_receive_window_size *receive_window_size);
size_t add_avp_challenge(uint8_t *avp_offset, const t_challenge *challenge);
size_t add_avp_tie_breaker(uint8_t *avp_offset,
		const t_tie_breaker *tie_breaker);
size_t add_avp_firmware_revision(uint8_t *avp_offset,
		const t_firmware_revision *firmware_revision);
size_t add_avp_vendor_name(uint8_t *avp_offset,
		const t_vendor_name *vendor_name);
size_t add_avp_challenge_response(uint8_t *avp_offset,
		const t_challenge_response *challenge_response);
size_t add_avp_result_code(uint8_t *avp_offset,
		const t_result_code *result_code);
size_t add_avp_assigned_session_id(uint8_t *avp_offset,
		const t_assigned_session_id *assigned_session_id);
size_t add_avp_call_serial_number(uint8_t *avp_offset,
		const t_call_serial_number *call_serial_number);
size_t add_avp_bearer_type(uint8_t *avp_offset,
		const t_bearer_type *bearer_type);
size_t add_avp_physical_channel_id(uint8_t *avp_offset,
		const t_physical_channel_id *physical_channel_id);
size_t add_avp_calling_number(uint8_t *avp_offset,
		const t_calling_number *calling_number);
size_t add_avp_called_number(uint8_t *avp_offset,
		const t_called_number *called_number);
size_t add_avp_sub_address(uint8_t *avp_offset,
		const t_sub_address *sub_address);
size_t add_avp_tx_connect_speed(uint8_t *avp_offset,
		const t_tx_connect_speed *tx_connect_speed);
size_t add_avp_framing_type(uint8_t *avp_offset,
		const t_framing_type *framing_type);
size_t add_avp_initial_received_lcp_confreq(uint8_t *avp_offset,
		const t_initial_received_lcp_confreq *initial_received_lcp_confreq);
size_t add_avp_last_sent_lcp_confreq(uint8_t *avp_offset,
		const t_last_sent_lcp_confreq *last_sent_lcp_confreq);
size_t add_avp_last_received_lcp_confreq(uint8_t *avp_offset,
		const t_last_received_lcp_confreq *last_received_lcp_confreq);
size_t add_avp_proxy_authen_type(uint8_t *avp_offset,
		const t_proxy_authen_type *proxy_authen_type);
size_t add_avp_proxy_authen_name(uint8_t *avp_offset,
		const t_proxy_authen_name * proxy_authen_name);
size_t add_avp_proxy_authen_challenge(uint8_t *avp_offset,
		const t_proxy_authen_challenge *proxy_authen_challenge);
size_t add_avp_proxy_authen_id(uint8_t *avp_offset,
		const t_proxy_authen_id *proxy_authen_id);
size_t add_avp_proxy_authen_response(uint8_t *avp_offset,
		const t_proxy_authen_response * proxy_authen_response);
size_t add_avp_private_group_id(uint8_t *avp_offset,
		const t_private_group_id *private_group_id);
size_t add_avp_rx_connect_speed(uint8_t *avp_offset,
		const t_rx_connect_speed *rx_connect_speed);
size_t add_avp_sequencing_required(uint8_t *avp_offset);
size_t add_avp_mimimum_bps(uint8_t *avp_offset,
		const t_minimum_bps *minimum_bps);
size_t add_avp_maximum_bps(uint8_t *avp_offset,
		const t_maximum_bps *maximum_bps);
size_t add_avp_q931_cause_code(uint8_t *avp_offset,
		const t_q931_cause_code *q931_cause_code);
size_t add_avp_call_errors(uint8_t *avp_offset,
		const t_call_errors *call_errors);
size_t add_avp_accm(uint8_t *avp_offset, const t_accm * accm);
#endif /* PARSER_H_ */
