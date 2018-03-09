/*
 * main.c
 *
 *  Created on: Jan 29, 2018
 *      Author: cicerali
 */
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>

#include <log.h>
#include <l2tp.h>

#include <parser.h>
#include <test.h>

#include <fsm.h>

//temp
#include <pthread.h>
#include <data.h>

extern int udp_fd;

extern l2tp_fsm_table l2tp_cce_fsm[];

int main(int argc, char *argv[])
{
	log_info("l2tp main process");
	init_globals();
	init_udp();
	init_tunnels();
	init_l2_sender();

	//temp
	pthread_t tid;
	pthread_create(&tid, NULL, packet_listener, NULL);
	//
	main_loop();
	return 0;
}

int init_udp(void)
{
	struct sockaddr_in addr;
	// Tunnel
	addr.sin_family = AF_INET;
	addr.sin_port = htons(L2TP_PORT);
	addr.sin_addr.s_addr = inet_addr(BIND_ADDRESS);
	udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_fd < 0)
	{
		log_error("ERROR opening socket");
		return -1;
	}

	int enable = 1;
	if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		log_error("setsockopt(SO_REUSEADDR) failed");
		return -1;
	}
	if (bind(udp_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		log_error("Error in UDP bind: %s", strerror(errno));
		return -1;
	}

	log_info("init_udp succesfull, udp_fd =  %d", udp_fd);
	return udp_fd;
}
