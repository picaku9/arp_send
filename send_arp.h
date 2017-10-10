#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h> //inet_pton()
#include <net/if.h> //ifreq header
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define ETHER_ADDR_LEN 6 

//libnet_header 참고 이더넷 구조체

struct libnet_ethernet_hdr {
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */    
};

struct ARP_Header {
	uint16_t arp_hw;
	uint16_t arp_pro;
	uint8_t arp_hlen;
	uint8_t arp_plen;
	uint16_t arp_op;
	uint8_t source_ether_addr[6];
	uint8_t source_ip_addr[4];
	uint8_t dest_ether_addr[6];
	uint8_t dest_ip_addr[4];
};

struct rq_packet {
	struct libnet_ethernet_hdr eth_header;
	struct ARP_Header arp_p;
};

void usage();
void print_ether(uint8_t *ether);
void print_ip(uint8_t *ip);
void get_dev_ether_addr(uint8_t *ether, char *dev);
void get_dev_ip_addr(uint8_t *ip, char *dev);
void rq_arp(struct rq_packet* p);