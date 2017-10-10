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



void usage() {
	printf("Should have syntax: send_arp <interface> <send ip> <target ip>\n");
}

void print_ether(uint8_t *ether){
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

void get_dev_ip_addr(uint8_t *ip, char *dev){
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4 * sizeof(*ip));
	close(s);
}

//libnet_header 참고 이더넷 구조체

struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */    
};

struct ARP_Header{
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

void rq_arp(struct rq_packet* p) {
	p->eth_header.ether_type = htons(0x0806);
	p->arp_p.arp_hw = htons(1);
	p->arp_p.arp_pro = htons(0x0800);
	p->arp_p.arp_hlen = (uint8_t)6;
	p->arp_p.arp_plen = (uint8_t)4;
	p->arp_p.arp_op = (uint16_t)1; //request
}


int main(int argc, char *argv[]) {
	//uint8_t* my_ether, sender_ether;
	uint8_t my_ether[6], sender_ether[6];
	//uint8_t *target_ether  : no need.
	//struct ARP_Header arp_hd, fake_arp_hd;
	struct rq_packet rq_p;
	char *dev;
	uint8_t my_ip[4];
	uint8_t send_ip[4];
	uint8_t target_ip[4];

	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t broadcast_ether[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	//step zero.
	if(argc<4) {
		//Should have syntax: send_arp <interface> <send ip> <target ip>
		usage(); 
		return -1;
	}
	printf("MY Interface : %s\n", argv[1]);
	// NOTICE.  sender recieves arp reply. 
	printf("Sender(victim) IP : %s\n", argv[2]);
	printf("FAKE Target IP : %s\n", argv[3]);
	dev = argv[1];
	inet_aton(argv[2], (in_addr *)send_ip);
	inet_aton(argv[3], (in_addr *)target_ip);
	get_dev_ether_addr(my_ether, dev);
	print_ether(my_ether);
	get_dev_ip_addr(my_ip, dev);
	printf("my ip ");
	print_ip(my_ip);

	/* 3 steps.
	1. send ARP reques
	2. receive ARP reply
	3. send ARP reply
	*/

	//1 send ARP request
	memcpy(rq_p.arp_p.dest_ip_addr, send_ip, 4);
	memcpy(rq_p.arp_p.source_ip_addr, my_ip, 4);
	memcpy(rq_p.eth_header.ether_shost, my_ether, 6);
	memcpy(rq_p.eth_header.ether_dhost, broadcast_ether, 6);
	memcpy(rq_p.arp_p.source_ether_addr, my_ether, 6);
	memcpy(rq_p.arp_p.dest_ether_addr, broadcast_ether, 6);
	rq_arp(&rq_p); // make the rest of request packet

	//print request packet
	printf("---------------ethernet protocol--------------------\n");
	print_ether(rq_p.eth_header.ether_dhost);
	print_ether(rq_p.eth_header.ether_shost);
	printf("ether type : 0x%04x\n", htons(rq_p.eth_header.ether_type));

	printf("---------------arp protocol--------------------\n");
	printf("Hardware type : 0x%04x\n", htons(rq_p.arp_p.arp_hw));
	printf("Protocol type : 0x0%x\n", htons(rq_p.arp_p.arp_pro));
	printf("Hardware size : %d\n", rq_p.arp_p.arp_hlen);
	printf("Protocol size : %d\n", rq_p.arp_p.arp_plen);
	printf("Opcode : %d\n", rq_p.arp_p.arp_op);
	printf("Source ");
	print_ether(rq_p.arp_p.source_ether_addr);
	printf("Destination ");
	print_ether(rq_p.arp_p.dest_ether_addr);
	printf("Source ip ");
	print_ip(rq_p.arp_p.source_ip_addr);
	printf("Destination ip ");
	print_ip(rq_p.arp_p.dest_ip_addr);

	// send packet
	pcap_t* handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);

	pcap_sendpacket(handle, (uint8_t*)&rq_p, sizeof(struct rq_packet));
	/*
        while(1) {
            tmp = pcap_next_ex(handle, &header, &get_packet);
            if(tmp<1) continue;
            tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
            if(ntohs(tmp_eth->ether_type) != 0X0806) continue;
            tmp_arp = (struct ARP_Header *)(get_packet+sizeof(libnet_ethernet_hdr));
            if(ntohs(tmp_arp->arp_hw) == 0x0001 && ntohs(tmp_arp->arp_op) == 0x2) {
                if(tmp_arp->source_ip_addr == rq_p.arp_p.dest_ip_addr) {
                    memcpy(sender_ether, tmp_arp->dest_ether_addr, 6);
                    break;
                }
            }
        }
    */
    
	printf("Sender ethernet address :");
	print_ether(sender_ether);
	return 0;
}
