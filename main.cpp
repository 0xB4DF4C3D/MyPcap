#define HAVE_REMOTE
#include <pcap\pcap.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//IP 헤더 구조체입니다.
typedef struct IP_HDR {
	u_char ipver : 4; // ipver 와 ihl은 4bit만 쓰기에 비트 필드를 사용하여 
	u_char ihl : 4;	  // 이렇게 짜 주었습니다.
	u_char tos;
	u_short total_len;
	u_short pkt_id;
	u_short flag : 3;
	u_short frag_offset : 13;
	u_char ttl;
	u_char protocol;
	u_short hdr_chksum;
	u_char sip[4]; // ip는 4byte지만 1byte씩 끊어 읽으므로 u_char형 배열로 선언 하였습니다.
	u_char dip[4];
	void* payload;
};

//TCP헤더 구조체입니다.
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

//UDP헤더 구조체입니다.
typedef struct UDP_HDR {
	u_short sport;
	u_short dport;
	u_short len;
	u_short chksum;
};

//TCP 헤더와 UDP헤더를 만들긴 했지만 이번 과제에서는 쓰지 않았습니다.
int main()
{
	//pcap 인터페이스 구조체를 선언합니다.
	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum; // 인터페이스 번호를 저장할 변수입니다.

	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메세지를 저장할 버퍼입니다.

	//모든 장치들을 찾아서 alldevs에 넣습니다. 만약 문제가 생긴다면 errbuf를 통해
	//에러 메세지를 출력하고 종료합니다.
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//장치 리스트를 출력합니다.
	for (d = alldevs; d; d = d->next) // pcap_if_t 가 링크드리스트 형식이라 d가 NULL일 때 까지 next로 다음 장치에 접근합니다.
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)	// 추가적인 설명이 있다면 출력하고
			printf(" (%s)\n", d->description);
		else // 없으면 없다고 출력합니다.
			printf(" (No description available)\n");
	}

	//만약 장치의 개수가 0개라면 에러메세지를 출력하고 종료합니다.
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//패킷을 캡쳐할 인터페이스 번호를 입력 받습니다.
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	//입력 받은 인터페이스 번호가 적절하지 않다면
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n"); // 범위를 초과했음을 알리고

		pcap_freealldevs(alldevs); // 모든 장치를 해제해준뒤
		return -1; // 종료합니다.
	}

	//지정한 인터페이스까지 이동합니다.
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	//어댑터를 엽니다.
	if ((adhandle = pcap_open_live(d->name,  // name of the device
		65536,     // portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL   // remote authentication
	)) == NULL)
	{ // 뭔가 문제가 생겼다면
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n"); // 에러메세지를 출력하고 
		
		pcap_freealldevs(alldevs); // 모든 장치를 해제해준뒤
		return -1; // 종료합니다.
	}

	//다 끝났으면 모든 장치를 해제해줍니다.
	pcap_freealldevs(alldevs);

	//캡쳐를 시작합니다.
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	//이더넷 타입을 뽑습니다.
	u_short Ether_type = ntohs(*((u_short*)(pkt_data + 12)));

	//IP 헤더를 선언합니다.
	IP_HDR * iph = (IP_HDR*)(pkt_data + 14);

	//이더넷 타입이 IP라면
	if (Ether_type == 0x800) {

		//Destination MAC을 출력합니다.
		printf("Destination MAC : ");
		for (int i = 0; i < 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 5)));

		//Source MAC을 출력합니다.
		printf("Source MAC : ");
		for (int i = 6; i < 6 + 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 6 + 5)));
		
		//이전에 뽑은 이더넷 타입을 출력해줍니다.
		printf("\nEther Type : 0x%04X (%s)\n", Ether_type, (Ether_type == 0x0800) ? "IP" : "ARP");

		//IP 헤더의 여러 정보들을 출력해줍니다.
		printf("IP ver : 0x%02X \t IP len : %4d \t Pkt Id : %4d\n", iph->ipver, ntohs(iph->ihl), ntohs(iph->pkt_id));
		printf("TTL : %3d \t Protocol : 0x%02X (%s) \n", iph->ttl, iph->protocol, (iph->protocol == 0x06) ? "TCP":"UDP");

		//Source IP와 Destination IP도 출력합니다.
		printf("SIP : %d.%d.%d.%d    ", iph->sip[0], iph->sip[1], iph->sip[2], iph->sip[3]);
		printf("DIP : %d.%d.%d.%d\n", iph->dip[0], iph->dip[1], iph->dip[2], iph->dip[3]);

		//Source Port와 Destination Port를 저장할 변수를 만들고
		u_short sport = ntohs((u_short)(iph->payload));
		u_short dport = ntohs(*(((u_short*)&iph->payload) + 1));

		//Source Port와 Destination Port를 출력합니다.
		printf("SPort : %d", sport);
		printf("    DPort : %d",dport);

		//한 패킷의 정보 출력이 모두 끝났다면 두번 개행해줍니다.
		printf("\n\n");
	}

	
}