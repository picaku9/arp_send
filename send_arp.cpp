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

void get_dev_ether_addr(uint8_t *ether, char *dev) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) perror("ioctl fail");
	memcpy(ether, ifr.ifr_hwaddr.sa_data, 6);
	close(s);
}

void get_dev_ip_addr(char *ip, char *dev){
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0) perror("ioctl fail");
	struct sockaddr_in *sin;
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(ip, inet_ntoa(sin->sin_addr), 15);
	printf("MY IP address : %s\n", ip);
	close(s);
}


void rq_arp(pcap_t* handle, struct rq_packet* p) {
	p->eth_header.ether_type = htons(0x0806);
	p->arp.ar_hrd = htons(1);
	p->arp.ar_pro = htons(0x0800);
	p->arp.ar_hln = (uint8_t)6;
	p->arp.ar_pln = (uint8_t)4;
	p->arp.ar_op = (uint16_t)1; //request
	pcap_sendpacket(handle, p, sizeof(struct rq_packet));
}


/*이제 사용 안함.
struct ip_addr {
	u_int8_t s_ip[4];
};
*/

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

struct rq_packet{
	struct libnet_ethernet_hdr eth_header;
	struct ARP_Header arp_packet;
};

int main(int argc, char *argv[]) {
	//uint8_t* my_ether, sender_ether;
	uint8_t my_ether[6], sender_ether[6];
	//uint8_t *target_ether  : no need.
	//struct ARP_Header arp_hd, fake_arp_hd;
	struct rq_packet rq_p;
	char* dev;
	char* my_ip, send_ip, target_ip;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t broadcast_ether[6]= "\xff\xff\xff\xff\xff\xff";

	//step zero.
	if(argc<4) {
		//Should have syntax: send_arp <interface> <send ip> <target ip>
		usage(); 
		return -1;
	}
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);

	printf("MY Interface : %s\n", argv[1]);
	// NOTICE.  sender recieves arp reply. 
	printf("Sender(victim) IP : %s\n", argv[2]);
	printf("FAKE Target IP : %s\n", argv[3]);
	dev = argv[1];

	send_ip = argv[2];
	target_ip = argv[3];
	
//	inet_pton(AF_INET, argv[2], &fake_arp_hd.dest_ip_addr);
//	inet_pton(AF_INET, argv[3], &fake_arp_hd.source_ip_addr);

	get_dev_ether_addr(my_ether, dev);
	print_ether(my_ether);
	get_dev_ip_addr(my_ip, dev);
	printf("my_ip : %s\n", my_ip);

	/* 3 steps.
	1. send ARP reques
	2. receive ARP reply
	3. send ARP reply
	*/
	
	//1 send ARP request
	inet_pton(AF_INET, my_ip, &rq_p.arp_packet.source_ip_addr);
	inet_pton(AF_INET, send_ip, &rq_p.arp_packet.dest_ip_addr);

	rq_p.eth_header.ether_shost = my_ether;
	rq_p.eth_header.ether_dhost = broadcast_ether;
	sender_ether = rq_arp(handle, rq_p); // ask sender ethernet address

	return 0;

}