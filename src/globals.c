/*
 * globals.c
 *
 *  Created on: Mar 8, 2018
 *      Author: cicerali
 */

#include <globals.h>

int udp_fd;

int l2_fd;

ipmap_t **ip_map = NULL;


uint32_t ppp_peer_ip = 16843009; // 1.1.1.1
char *interface = "ens33";
struct sockaddr_ll device;
uint8_t ether_frame[2000];

int init_globals()
{
	ip_map = (ipmap_t **) malloc(IPMAP_MAX);
	for(int i = 0; i < IPMAP_MAX; i++)
	{
		ip_map[i] = (ipmap_t *) malloc(sizeof(ipmap_t));
		memset(ip_map[i], 0, sizeof(ipmap_t));
	}

	log_info("Allocated size = %dX%d(bytes) = %.4fKB", IPMAP_MAX, sizeof(ipmap_t), (double)(IPMAP_MAX*sizeof(ipmap_t))/1024);
	log_info("Globals initializations done");
	return 0;
}
