#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char  tos;			// Type of service 
	u_short tlen;		   // Total length 
	u_short identification; // Identification
	u_short flags_fo;	   // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;			// Time to live
	u_char  proto;		  // Protocol
	u_short crc;			// Header checksum
	ip_address  saddr;	  // Source address
	ip_address  daddr;	  // Destination address
	u_int   op_pad;		 // Option + Padding
}ip_header;

/* TCP header */
typedef struct tcp_header{
	u_short th_sport;		// source port
	u_short th_dport;		// destination port
	u_int th_seq;			// sequence number
	u_int th_ack;			// acknowledgement number
	u_char th_offx2;		// data offset, rsvd
	u_char th_flags;		// tcp flags
	u_short th_win;			// window
	u_short th_sum;			// checksum
	u_short th_urp;			// urgent pointer
}tcp_header;

// prototype of the packet handler
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#define ether_len 14
int sockfd;
struct sockaddr_in target; //Socket address information

int main(int argc, char **argv) {   

	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter = NULL;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;

	// socket to php
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 0);			// Request WinSock v2.0
	WSAStartup(wVersionRequested, &wsaData);		// Load WinSock DLL
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); //Create socket
	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET; // address family Internet
	target.sin_port = htons (1234); //Port to connect on
	target.sin_addr.s_addr = inet_addr ("127.0.0.1"); //Target IP
	// set TCP_NODELAY for sure
	//int optval = 1;
	//setsockopt(sockfd, IPPROTO_IP, TCP_NODELAY, (char *)&optval, sizeof(optval));
	if(connect(sockfd, (SOCKADDR *)&target, sizeof(target)) != SOCKET_ERROR){
		printf("Connected to PacketParser <3\n");
	}

	if(argc < 3) {
		
		//printf("\nPrinting the device list:\n");
		// The user didn't provide a packet source: Retrieve the local device list
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			return -1;
		}
		/*
		// Print the list 
		for(d=alldevs; d; d=d->next) {
			printf("%d. %s\n	", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
		
		if (i==0) {
			fprintf(stderr,"No interfaces found! Exiting.\n");
			return -1;
		}
		*/
		//printf("Enter the interface number (1-%d):",i);
		//scanf_s("%d", &inum);
		
		inum = 1;
		/*
		if (inum < 1 || inum > i) {
			printf("\nInterface number out of range.\n");

			// Free the device list
			pcap_freealldevs(alldevs);
			return -1;
		}
		*/
		// Jump to the selected adapter
		for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
		
		// Open the device
		if ( (fp= pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL) {
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		} else {
			printf("Selected Adapter %s\n	%s\n\n", d->name, d->description);
		}
	} else {
		// Do not check for the switch type ('-s')
		if ( (fp= pcap_open(argv[2], 65536, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL) {
			fprintf(stderr,"\nError opening source: %s\n", errbuf);
			return -1;
		}
	}
	NetMask=0xffffff;
	filter = "(tcp port 6900 || tcp port 7000 || tcp port 4501) && tcp[tcpflags] & tcp-push != 0";
	//compile the filter
	if(pcap_compile(fp, &fcode, filter, 1, NetMask) < 0) {
		fprintf(stderr,"\nError compiling filter: wrong syntax.\n");

		pcap_close(fp);
		return -3;
	}

	//set the filter
	if(pcap_setfilter(fp, &fcode)<0) {
		fprintf(stderr,"\nError setting the filter\n");

		pcap_close(fp);
		return -4;
	}
	/* start the capture */
	pcap_loop(fp, 0, packet_handler, NULL);

	return 0;
}
// Callback function invoked by libpcap for every incoming packet
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	// ip header and len
	ip_header *ih;
	int ip_len;
	// tcp header and len
	tcp_header *th;
	int tcp_len;
	// payload and len
	char *tcpPayload;
	int size_payload;
	
	u_short sport,dport;

	// Unused variable
	(VOID)(param);

	// retireve the position of the ip header
	ih = (ip_header *) (pkt_data + ether_len);
	ip_len = (ih->ver_ihl & 0xf) * 4;

	// retireve the position of the tcp header 
	th = (tcp_header *) (pkt_data + ether_len + ip_len);
	tcp_len = th->th_offx2/4;

	// retrieve the position of payload
	tcpPayload = (char *)pkt_data + ether_len + ip_len + tcp_len;

	size_payload = ntohs(ih->tlen) - (ip_len + tcp_len);
	// convert from network byte order to host byte order
	sport = ntohs( th->th_sport );
	dport = ntohs( th->th_dport );

	tcpPayload = tcpPayload - 2; // shift pointer 2 bytes left
	size_payload = size_payload + 2; // add these 2 bytes to len

	//tcp port 6900 || tcp port 7000 || tcp port 4501)
	if(sport == 6900 || sport == 7000 || sport == 4501){
		tcpPayload[0] = 'R'; tcpPayload[1] = 'R';
	} else {
		tcpPayload[0] = 'S'; tcpPayload[1] = 'S';
	}

	printf("Packet (%d bytes)\n", size_payload);
	// print ip addresses and tcp ports
	//printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,sport,ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4,dport);
	//printf("%x\n", *tcpPayload);
	if(send(sockfd,(const char *)tcpPayload,size_payload,0) == SOCKET_ERROR){
		if(connect(sockfd, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR){
			printf("Parser not listening\n");
		} else {
			printf("Connected to PacketParser <3\n");
			send(sockfd,(const char *)tcpPayload,size_payload,0);
		}
	}
}