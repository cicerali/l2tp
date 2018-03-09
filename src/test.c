/*
 * test.c
 *
 *  Created on: Feb 23, 2018
 *      Author: cicerali
 */

#include <test.h>

extern int udp_fd;

void make_header(l2tp_control_message *message)
{
	message->header.type_flags = 0xC802;
	message->header.tunnel_id = 12;
	message->header.session_id = 155;
	message->header.ns = 17;
	message->header.nr = 27;
}

void test_sccrq(l2tp_control_message *message)
{
	log_debug("testing --> SCCRQ");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = SCCRQ;
	message->sccrq.p_ver.ver = 1;
	message->sccrq.p_ver.rev = 0;
	message->sccrq.f_cap.asynchronous = true;
	message->sccrq.f_cap.synchronous = true;
	message->sccrq.tunnel_id = 18994;
	message->sccrq.b_cap_present = true;
	message->sccrq.b_cap.analog = true;
	message->sccrq.b_cap.digital = false;
	memcpy(message->sccrq.h_name.value, "109.6.1.72", strlen("109.6.1.72"));
	message->sccrq.h_name.length = strlen("109.6.1.72");
	message->sccrq.window_present = true;
	message->sccrq.window = 2;
	message->sccrq.challenge_present = true;
	message->sccrq.chal.length = 16;
	memcpy(message->sccrq.chal.value,
			"\x50\x81\x54\xfa\x78\x78\x43\x6c\x33\x1b\x3a\x2b\x11\x43\x13\x73",
			16);
	message->sccrq.tie_present = true;
	message->sccrq.tie = 1453;
	message->sccrq.f_rev_present = true;
	message->sccrq.f_rev = 1680;
	message->sccrq.v_name_present = true;
	memcpy(message->sccrq.v_name.value, "xelerance.com",
			strlen("xelerance.com"));
	message->sccrq.v_name.length = strlen("xelerance.com");

	send_receive(message);
}

void test_sccrp(l2tp_control_message * message)
{
	log_debug("testing --> SCCRP");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = SCCRP;
	message->sccrp.p_ver.ver = 1;
	message->sccrp.p_ver.rev = 0;
	message->sccrp.f_cap.asynchronous = false;
	message->sccrp.f_cap.synchronous = false;
	memcpy(message->sccrp.h_name.value, "6pe", strlen("6pe"));
	message->sccrp.h_name.length = strlen("6pe");
	message->sccrp.tunnel_id = 1527;
	message->sccrp.b_cap_present = true;
	message->sccrp.b_cap.analog = true;
	message->sccrp.b_cap.digital = false;
	message->sccrp.f_rev_present = true;
	message->sccrp.f_rev = 8016;
	message->sccrp.v_name_present = true;
	memcpy(message->sccrp.v_name.value, "ozan.com", strlen("ozan.com"));
	message->sccrp.v_name.length = strlen("ozan.com");
	message->sccrp.window_present = true;
	message->sccrp.window = 3;
	message->sccrp.challenge_present = true;
	message->sccrp.chal.length = 16;
	memcpy(message->sccrp.chal.value,
			"\x50\x81\x54\xfa\x78\x78\x43\x6c\x33\x1b\x3a\x2b\x11\x43\x13\x73",
			16);
	message->sccrp.c_resp_present = true;
	memcpy(message->sccrp.chal_resp.value,
			"\x50\x81\x54\xfa\x78\x78\x43\x6c\x33\x1b\x3a\x2b\x11\x43\x13\x37",
			16);
	send_receive(message);
}

void test_scccn(l2tp_control_message * message)
{
	log_debug("testing --> SCCCN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = SCCCN;
	message->scccn.c_resp_present = true;
	memcpy(message->scccn.chal_resp.value,
			"\x50\x81\x54\xfa\xaa\x78\x43\x7c\x33\x1b\x3a\x3b\x11\x43\x13\xcc",
			16);
	send_receive(message);
}

void test_stopccn(l2tp_control_message * message)
{
	log_debug("testing --> StopCCN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = StopCCN;
	message->stopccn.tunnel_id = 1881;
	message->stopccn.r_code.code = 2;
	message->stopccn.r_code.error_present = true;
	message->stopccn.r_code.error = 7;
	message->stopccn.r_code.error_massage_present = true;
	message->stopccn.r_code.length = strlen("Why the halfling!");
	memcpy(message->stopccn.r_code.error_massage, "Why the halfling!",
			strlen("Why the halfling!"));
	send_receive(message);
}

void test_hello(l2tp_control_message * message)
{
	log_debug("testing --> Hello");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = HELLO;
	send_receive(message);
}

void test_icrq(l2tp_control_message * message)
{
	log_debug("testing --> ICRQ");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = ICRQ;
	message->icrq.session_id = 1526;
	message->icrq.s_number = 3;
	message->icrq.bearer_type_present = true;
	message->icrq.b_type.analog = true;
	message->icrq.b_type.digital = false;
	message->icrq.physical_channel_present = true;
	message->icrq.channel_id = 25;
	message->icrq.calling_number_present = true;
	message->icrq.calling_number.length = strlen("FA123568CD25");
	memcpy(message->icrq.calling_number.value, "FA123568CD25",
			strlen("FA123568CD25"));
	message->icrq.called_number_present = true;
	message->icrq.called_number.length = strlen("123456AA98CC");
	memcpy(message->icrq.called_number.value, "123456AA98CC",
			strlen("123456AA98CC"));
	message->icrq.sub_address_present = true;
	message->icrq.address.length = strlen("netas");
	memcpy(message->icrq.address.value, "netas", strlen("netas"));
	send_receive(message);
}

void test_iccp(l2tp_control_message * message)
{
	log_debug("testing --> ICRP");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = ICRP;
	message->icrp.session_id = 1843;
	send_receive(message);
}

void test_iccn(l2tp_control_message * message)
{
	log_debug("testing --> ICCN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = ICCN;
	message->iccn.tx = 33554432;
	message->iccn.f_type.asynchronous = false;
	message->iccn.f_type.synchronous = true;
	message->iccn.initial_lcp_confreq_present = true;
	message->iccn.initial_lcp_confreq.length = strlen("123456789");
	memcpy(message->iccn.initial_lcp_confreq.value, "123456789",
			strlen("123456789"));
	message->iccn.last_sent_lcp_confreq_present = true;
	message->iccn.last_sent_lcp_confreq.length = strlen("123456");
	memcpy(message->iccn.last_sent_lcp_confreq.value, "123456",
			strlen("123456"));
	message->iccn.last_received_lcp_confreq_present = true;
	message->iccn.last_received_lcp_confreq.length = strlen("123");
	memcpy(message->iccn.last_received_lcp_confreq.value, "123", strlen("123"));
	message->iccn.authen_type_present = true;
	message->iccn.authen_type = 2;
	message->iccn.authen_name_present = true;
	message->iccn.authen_name.length = strlen("netast-test");
	memcpy(message->iccn.authen_name.value, "netast-test",
			strlen("netast-test"));
	message->iccn.authen_challenge_present = true;
	message->iccn.authen_challenge.length = strlen("789456");
	memcpy(message->iccn.authen_challenge.value, "789456", strlen("789456"));
	message->iccn.authen_id_present = true;
	message->iccn.authen_id = 35;
	message->iccn.authen_response_present = true;
	message->iccn.authen_response.length = strlen("password");
	memcpy(message->iccn.authen_response.value, "password", strlen("password"));
	message->iccn.group_id_present = true;
	message->iccn.group_id.length = strlen("test.mec.com");
	memcpy(message->iccn.group_id.value, "test.mec.com",
			strlen("test.mec.com"));
	message->iccn.rx_speed_present = true;
	message->iccn.rx = 4194304;
	message->iccn.sequencing_present = true;
	send_receive(message);
}

void test_ocrq(l2tp_control_message * message)
{
	log_debug("testing --> OCRQ");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = OCRQ;
	message->ocrq.session_id = 13;
	message->ocrq.s_number = 17;
	message->ocrq.min_bps = 1048576;
	message->ocrq.max_bps = 33554432;
	message->ocrq.b_type.analog = false;
	message->ocrq.b_type.digital = true;
	message->ocrq.f_type.synchronous = false;
	message->ocrq.f_type.asynchronous = true;
	message->ocrq.called_number.length = strlen("564789521");
	memcpy(message->ocrq.called_number.value, "564789521", strlen("564789521"));
	message->ocrq.sub_address_present = true;
	message->ocrq.address.length = strlen("yenisehir");
	memcpy(message->ocrq.address.value, "yenisehir", strlen("yenisehir"));
	send_receive(message);
}

void test_ocrp(l2tp_control_message * message)
{
	log_debug("testing --> OCRP");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = OCRP;
	message->ocrp.session_id = 23;
	message->ocrp.physical_channel_present = true;
	message->ocrp.channel_id = 12;
	send_receive(message);
}

void test_occn(l2tp_control_message * message)
{
	log_debug("testing --> OCCN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = OCCN;
	message->occn.tx = 8388608;
	message->occn.f_type.synchronous = true;
	message->occn.f_type.asynchronous = false;
	message->occn.rx_speed_present = true;
	message->occn.rx = 1048576;
	message->occn.sequencing_present = true;
	send_receive(message);
}

void test_cdn(l2tp_control_message * message)
{
	log_debug("testing --> CDN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = CDN;
	message->cdn.r_code.code = 2;
	message->cdn.r_code.error_present = true;
	message->cdn.r_code.error = 7;
	message->cdn.r_code.error_massage_present = true;
	message->cdn.r_code.length = strlen("Why the halfling!");
	memcpy(message->cdn.r_code.error_massage, "Why the halfling!",
			strlen("Why the halfling!"));
	message->cdn.session_id = 571;
	message->cdn.cause_code_preset = true;
	message->cdn.c_code.c_code = 5;
	message->cdn.c_code.msg_code = 7;
	message->cdn.c_code.length = strlen("Ne olacak boyle!");
	memcpy(message->cdn.c_code.message, "Ne olacak boyle!",
			strlen("Ne olacak boyle!"));
	send_receive(message);
}

void test_wen(l2tp_control_message * message)
{
	log_debug("testing --> WEN");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = WEN;
	message->wen.c_errors.crc_errors = 15;
	message->wen.c_errors.framing_errors = 155;
	message->wen.c_errors.hardware_overruns = 1578;
	message->wen.c_errors.buffer_overruns = 159874652;
	message->wen.c_errors.timeout_errors = 1527;
	message->wen.c_errors.alignment_errors = 89;
	send_receive(message);
}

void test_sli(l2tp_control_message * message)
{
	log_debug("testing --> SLI");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = SLI;
	message->sli.accm.rcv_accm = 1356;
	message->sli.accm.rcv_accm = 589;
	send_receive(message);
}

void test_zlb(l2tp_control_message * message)
{
	log_debug("testing --> ZLB");
	memset(message, 0, sizeof(l2tp_control_message));
	make_header(message);
	message->message_type = ZLB;
	send_receive(message);
}

void test_l2tp()
{
	l2tp_control_message message;
	test_sccrq(&message);
	test_sccrp(&message);
	test_scccn(&message);
	test_stopccn(&message);
	test_hello(&message);
	test_icrq(&message);
	test_iccp(&message);
	test_iccn(&message);
	test_ocrq(&message);
	test_ocrp(&message);
	test_occn(&message);
	test_cdn(&message);
	test_wen(&message);
	test_sli(&message);
	test_zlb(&message);
}

void send_receive(l2tp_control_message * message)
{
	uint8_t buf[1500];
	size_t length = 0;
	log_info("Encoding l2tp control message");
	l2tp_control_encode(buf, &length, message);
	struct sockaddr_in remote;
	remote.sin_family = AF_INET;
	remote.sin_port = htons(1701);
	inet_aton("127.0.0.1", &remote.sin_addr.s_addr);
	log_info("udp_fd : %d, length : %d", udp_fd, length);
	socklen_t sock_len = sizeof(remote);
	int rc = sendto(udp_fd, buf, length, 0, (struct sockaddr*) &remote,
			sock_len);
	log_info("Check error sendto rc = %d: error: %s", rc, strerror(errno));
	rc = recvfrom(udp_fd, buf, 1500, 0, (struct sockaddr*) &remote, &sock_len);
	log_info("Check error recvfrom rc = %d: error: %s", rc, strerror(errno));
	log_info("Cleaning l2tp control message");
	memset(message, 0, sizeof(l2tp_control_message));
	log_info("Decoding received message");
	rc = l2tp_control_decode(buf, rc, message);
	log_info("Cleaning buffer");
	memset(buf, 0, 1500);
	log_info("Encoding again for compare enocede-decode results");
	l2tp_control_encode(buf, &length, message);
	rc = sendto(udp_fd, buf, length, 0, (struct sockaddr*) &remote, sock_len);
	log_info("Check error sendto rc = %d: error: %s", rc, strerror(errno));
	recvfrom(udp_fd, buf, 1500, 0, (struct sockaddr*) &remote, &sock_len);
}
