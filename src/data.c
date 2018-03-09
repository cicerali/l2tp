/*
 * data.c
 *
 *  Created on: Mar 7, 2018
 *      Author: cicerali
 */

#include <data.h>

extern int udp_fd;
extern int l2_fd;
extern tunnel_t **tunnels;
extern ipmap_t **ip_map;
extern char *interface;
extern struct sockaddr_ll device;
extern uint8_t ether_frame[2000];

void* packet_listener(void *param)
{

	int rcvsd;
	uint8_t buf[2000];
	struct ifreq ifr;
	uint8_t my_mac[6];
	struct sockaddr_ll from;
	struct sockaddr_ll sock_address;
	char mac_addr[20] =
	{ 0 };
	socklen_t fromlen = sizeof(from);

	if ((rcvsd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		log_error(
				"socket() failed to obtain a receive socket descriptor RC = %d",
				errno);
		close(rcvsd);
		pthread_exit(NULL);
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);

	if (ioctl(rcvsd, SIOCGIFHWADDR, &ifr) < 0)
	{
		log_error("ioctl() failed to get source MAC address RC = %d", errno);
		close(rcvsd);
		pthread_exit(NULL);
	}

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
	sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", my_mac[0], my_mac[1],
			my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	log_info("MAC address for interface %s is %s", interface, mac_addr);

	memset(&sock_address, 0, sizeof(sock_address));
	sock_address.sll_family = AF_PACKET;
	sock_address.sll_protocol = htons(ETH_P_ALL);
	sock_address.sll_ifindex = if_nametoindex(interface);
	log_info("Index for interface %s is %i", interface,
			sock_address.sll_ifindex);
	if (bind(rcvsd, (struct sockaddr*) &sock_address, sizeof(sock_address)) < 0)
	{
		log_error("bind failed RC = %d", errno);
		close(rcvsd);
		pthread_exit(NULL);
	}

	struct ether_header *eh = (struct ether_header *) buf;
	struct ip *iphdr;
	char dest[16] =
	{ 0 };
	int rc;

	uint8_t send_buf[2000];
	socklen_t sock_len = sizeof(struct sockaddr_in);
	log_info("Waiting packet from interface %s", interface);
	while (1)
	{

		rc = recvfrom(rcvsd, buf, 2000, 0, (struct sockaddr *) &from, &fromlen);
		if (rc < 0)
		{
			log_error("recvfrom() failed RC = %d", errno);
			usleep(100);
			continue;
		}
		//        else if (from.sll_pkttype != PACKET_OUTGOING && ntohs(from.sll_protocol) == ETH_P_IP)
		else if (from.sll_pkttype != PACKET_OUTGOING
				&& ntohs(from.sll_protocol) == ETH_P_IP
				&& eh->ether_dhost[0] == my_mac[0]
				&& eh->ether_dhost[1] == my_mac[1]
				&& eh->ether_dhost[2] == my_mac[2]
				&& eh->ether_dhost[3] == my_mac[3]
				&& eh->ether_dhost[4] == my_mac[4]
				&& eh->ether_dhost[5] == my_mac[5])
		{
			iphdr = (struct ip*) &buf[14]; //skip first 14 bytes(ethernet layer)

			strcpy(dest, inet_ntoa(iphdr->ip_dst));
			//log_debug("Receive success from %s to %s ",
			//		inet_ntoa(iphdr->ip_src), dest);
			session_t *local_sess = find_session(ntohl(iphdr->ip_dst.s_addr));
			if (local_sess != NULL)
			{
				//log_debug("Destination to my static peer : %s", dest);
				int rc = l2tp_encode_msg(send_buf, 2000, (uint8_t *) iphdr,
						ntohs(iphdr->ip_len),
						PPPIPV4, local_sess);

				rc = sendto(udp_fd, send_buf, rc, 0,
						(struct sockaddr*) &tunnels[local_sess->local_tunnel]->remote_ip, sock_len);
				if (rc <= 0)
				{
					log_info("Error occurred, sendto rc = %d: error: %s", rc,
							strerror(errno));
				}
			}
			else
			{
				log_error("Peer map not implemented yet ignoring : %s", dest);
			}

		}
		else
		{
//			log_error("NOt to us, is outgoing :%s, is ip protoco:%s, proto :%d", (from.sll_pkttype == PACKET_OUTGOING)?"OUTGOING PACKET":"INCOMING PACKET",
//					(ntohs(from.sll_protocol) == ETH_P_IP)?"IP PROTOCOL":"NOT IP", ntohs(from.sll_protocol));
//
//			log_error("PACKET MAC ADDRESSSES: dest:my_mac -> %d:%d, %d:%d, %d:%d, %d:%d, %d:%d, %d:%d",
//			eh->ether_dhost[0], my_mac[0],
//			eh->ether_dhost[1], my_mac[1],
//			eh->ether_dhost[2], my_mac[2],
//			eh->ether_dhost[3], my_mac[3],
//			eh->ether_dhost[4], my_mac[4],
//			eh->ether_dhost[5], my_mac[5]);
		}

	}

	return NULL;
}

int init_l2_sender()
{
	struct ifreq ifr;
	char dst_mac[6];

	// Submit request for a socket descriptor.
	if ((l2_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		log_error(
				"socket() failed to obtain a receive socket descriptor RC = %d",
				errno);
		close(l2_fd);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
		if (ioctl(l2_fd, SIOCGIFHWADDR, &ifr) < 0)
		{
			log_error("ioctl() failed to get source MAC address RC = %d", errno);
			close(l2_fd);
			return -1;
		}
		char mac_addr[20] =
		{ 0 };
		uint8_t src_mac[6];
		memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
		sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", src_mac[0], src_mac[1],
				src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
		log_info("MAC address for interface %s is %s", interface, mac_addr);

		// Find interface index from interface name and store index in
		// struct sockaddr_ll device, which will be used as an argument of sendto().
		if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
		{
			log_error("if_nametoindex() failed to obtain interface index RC = %d",
					errno);
			close(l2_fd);
			return -1;
		}
		log_info("Index for interface %s is %i", interface, device.sll_ifindex);

		// Set destination MAC address: you need to fill these out
		dst_mac[0] = 0x00;
		dst_mac[1] = 0x50;
		dst_mac[2] = 0x56;
		dst_mac[3] = 0xba;
		dst_mac[4] = 0x8f;
		dst_mac[5] = 0x4c;

		// Destination and Source MAC addresses
		memcpy(ether_frame, dst_mac, 6);
		memcpy(ether_frame + 6, src_mac, 6);

		// Next is ethernet type code (ETH_P_IP for IPv4).
		// http://www.iana.org/assignments/ethernet-numbers
		ether_frame[12] = ETH_P_IP / 256;
		ether_frame[13] = ETH_P_IP % 256;

		// Fill out sockaddr_ll.
		device.sll_family = AF_PACKET;
		memcpy(device.sll_addr, src_mac, 6);
		device.sll_halen = htons(6);

		return 0;
}

int process_ppp_ipv4(uint8_t *buf, int length)
{

	int rc;
	int frame_length; // = ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;


	frame_length = 14 + length;
	memcpy(ether_frame + 14, buf, length);
	rc = sendto(l2_fd, ether_frame, frame_length, 0, (struct sockaddr *) &device,
			sizeof(device));
	if (rc < 0)
	{
		log_error("sendto() failed RC = %d sleep 100ms and continue", errno);
	}
	else
	{
		//log_info("Sent success");
	}
	return 0;
}

int l2tp_encode_msg(uint8_t *buf, int buf_size, uint8_t *ppp, int ppp_len,
		uint16_t ppp_type, session_t *sess)
{
	int pack_size = 0;
	uint8_t *offset = buf;
	uint16_t hdr = 0x0002;

	*(uint16_t*) (buf + 0) = htobe16(hdr);
	*(uint16_t*) (buf + 2) = htobe16(tunnels[sess->local_tunnel]->remote_tunnel);
	*(uint16_t*) (buf + 4) = htobe16(sess->remote_session);

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

session_t * find_session(uint32_t ipv4_address)
{
	if (ip_map != NULL)
	{
		for (int i = 0; i < IPMAP_MAX; i++)
		{
			if (ip_map[i] != NULL && ip_map[i]->ip_addr == ipv4_address)
			{
				return ip_map[i]->local_session;
			}
		}
	}

	return NULL;
}
