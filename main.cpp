#define HAVE_REMOTE
#include <pcap\pcap.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

typedef struct IP_HDR {
	u_char ipver : 4;
	u_char ihl : 4;
	u_char tos;
	u_short total_len;
	u_short pkt_id;
	u_short flag : 3;
	u_short frag_offset : 13;
	u_char ttl;
	u_char protocol;
	u_short hdr_chksum;
	u_char sip[4];
	u_char dip[4];
	void* payload;
};

typedef struct TCP_HDR {
	u_short sport;
	u_short dport;
	u_int seq;
	u_int ack;
	u_char offset : 4;
	u_short flag : 12;
	u_short window;
	u_short chksum;
	u_short urgptr;
	u_int tcpopt;
};

typedef struct UDP_HDR {
	u_short sport;
	u_short dport;
	u_short len;
	u_short chksum;
};

int main()
{

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,  // name of the device
		65536,     // portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL   // remote authentication
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}


	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{


	u_short Ether_type = ntohs(*((u_short*)(pkt_data + 12)));

	IP_HDR * iph = (IP_HDR*)(pkt_data + 14);

	if (Ether_type == 0x800) {

		printf("Destination MAC : ");
		for (int i = 0; i < 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 5)));

		printf("Source MAC : ");
		for (int i = 6; i < 6 + 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 6 + 5)));
		

		printf("\nEther Type : 0x%04X (%s)\n", Ether_type, (Ether_type == 0x0800) ? "IP" : "ARP");

		printf("IP ver : 0x%02X \t IP len : %4d \t Pkt Id : %4d\n", iph->ipver, ntohs(iph->ihl), ntohs(iph->pkt_id));
		printf("TTL : %3d \t Protocol : 0x%02X (%s) \n", iph->ttl, iph->protocol, (iph->protocol == 0x06) ? "TCP":"UDP");

		printf("SIP : %d.%d.%d.%d    ", iph->sip[0], iph->sip[1], iph->sip[2], iph->sip[3]);
		printf("DIP : %d.%d.%d.%d\n", iph->dip[0], iph->dip[1], iph->dip[2], iph->dip[3]);

		u_short sport = ntohs((u_short)(iph->payload));
		u_short dport = ntohs(*(((u_short*)&iph->payload) + 1));

		printf("SPort : %d", sport);
		printf("    DPort : %d",dport);

		printf("\n\n");
	}

	
}


/*
struct nib {
	unsigned int nib1 : 4;
	unsigned int nib2 : 4;
};
if (*((unsigned char*)(pkt_data + 23)) != 0x11 || 1 == 1) {
	printf("Dest Mac : ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", *((unsigned char*)(pkt_data + 0 + i)));
	printf("%02X     ", *((unsigned char*)(pkt_data + 0 + 6)));

	printf("Src Mac : ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", *((unsigned char*)(pkt_data + 6 + i)));
	printf("%02X     ", *((unsigned char*)(pkt_data + 6 + 6)));


	printf("type : ");
	for (int i = 0; i < 2; i++)
		printf("%02X", *((unsigned char*)(pkt_data + 12 + i)));
	printf("\n");

	printf("IP ver : %X     IHL : %02X     ", ((nib*)(pkt_data + 14))->nib2, ((nib*)(pkt_data + 14))->nib1);
	printf("TOS : %X     ", *((unsigned char*)(pkt_data + 15)));
	int total_length = ntohs((u_char)pkt_data + 16);
	printf("Total Length : %#X\n", total_length);

	for (int i = 0; i<16; i++)
		printf("%d.", *((unsigned char*)(pkt_data + 22 + i)));
	//printf("protcol : %X", *((unsigned char*)(pkt_data + 23)));
	//	dport = ntohs((u_char)pkt_data + 34);
	//	printf("dport : %d", dport);
*/