/*
 * data.h
 *
 *  Created on: Mar 7, 2018
 *      Author: cicerali
 */

#ifndef DATA_H_
#define DATA_H_

#define _BSD_SOURCE
#include <sys/ioctl.h> // macro ioctl is defined
#include <net/if.h>
#include <netinet/ip.h>
#include <netpacket/packet.h> //sockaddr_ll
#include <net/ethernet.h> //ETH_P_ALL

#include <arpa/inet.h> //inet_ntoa

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <log.h>

#include <globals.h>
#include <ppp.h>

void* packet_listener(void *param);
int l2tp_encode_msg(uint8_t *buf, int buf_size, uint8_t *ppp, int ppp_len,
		uint16_t ppp_type, session_t *sess);

int process_ppp_ipv4(uint8_t *buf, int length);

session_t * find_session(uint32_t ipv4_address);

int init_l2_sender();


#endif /* DATA_H_ */
