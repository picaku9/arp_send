#include "send_arp.h"

void usage() {
	printf("Should have syntax: send_arp <interface> <send ip> <target ip>\n");
}

void print_ether(uint8_t *ether) {
	printf("MAC address : ");
	for (int i = 0; i < 5; i++) {
		printf("%02x:", ether[i]);
	}
	printf("%02x\n", ether[5]);
}

void print_ip(uint8_t *ip) {
	printf("IP address : ");
	for (int i = 0; i < 3; i++) {
		printf("%d.", ip[i]);
	}
	printf("%d\n", ip[3]);
}

void get_dev_ether_addr(uint8_t *ether, char *dev) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ether, ifr.ifr_hwaddr.sa_data, 6);
	close(s);
}

void get_dev_ip_addr(uint8_t *ip, char *dev) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4 * sizeof(*ip));
	close(s);
}

void rq_arp(struct rq_packet* p) {
	p->eth_header.ether_type = htons(0x0806);
	p->arp_p.arp_hw = htons(1);
	p->arp_p.arp_pro = htons(0x0800);
	p->arp_p.arp_hlen = (uint8_t)6;
	p->arp_p.arp_plen = (uint8_t)4;
	p->arp_p.arp_op = (uint16_t)1; //request
}