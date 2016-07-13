#define HAVE_REMOTE
#include <pcap\pcap.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//IP ��� ����ü�Դϴ�.
typedef struct IP_HDR {
	u_char ipver : 4; // ipver �� ihl�� 4bit�� ���⿡ ��Ʈ �ʵ带 ����Ͽ� 
	u_char ihl : 4;	  // �̷��� ¥ �־����ϴ�.
	u_char tos;
	u_short total_len;
	u_short pkt_id;
	u_short flag : 3;
	u_short frag_offset : 13;
	u_char ttl;
	u_char protocol;
	u_short hdr_chksum;
	u_char sip[4]; // ip�� 4byte���� 1byte�� ���� �����Ƿ� u_char�� �迭�� ���� �Ͽ����ϴ�.
	u_char dip[4];
	void* payload;
};

//TCP��� ����ü�Դϴ�.
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

//UDP��� ����ü�Դϴ�.
typedef struct UDP_HDR {
	u_short sport;
	u_short dport;
	u_short len;
	u_short chksum;
};

//TCP ����� UDP����� ����� ������ �̹� ���������� ���� �ʾҽ��ϴ�.
int main()
{
	//pcap �������̽� ����ü�� �����մϴ�.
	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum; // �������̽� ��ȣ�� ������ �����Դϴ�.

	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE]; // ���� �޼����� ������ �����Դϴ�.

	//��� ��ġ���� ã�Ƽ� alldevs�� �ֽ��ϴ�. ���� ������ ����ٸ� errbuf�� ����
	//���� �޼����� ����ϰ� �����մϴ�.
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//��ġ ����Ʈ�� ����մϴ�.
	for (d = alldevs; d; d = d->next) // pcap_if_t �� ��ũ�帮��Ʈ �����̶� d�� NULL�� �� ���� next�� ���� ��ġ�� �����մϴ�.
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)	// �߰����� ������ �ִٸ� ����ϰ�
			printf(" (%s)\n", d->description);
		else // ������ ���ٰ� ����մϴ�.
			printf(" (No description available)\n");
	}

	//���� ��ġ�� ������ 0����� �����޼����� ����ϰ� �����մϴ�.
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//��Ŷ�� ĸ���� �������̽� ��ȣ�� �Է� �޽��ϴ�.
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	//�Է� ���� �������̽� ��ȣ�� �������� �ʴٸ�
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n"); // ������ �ʰ������� �˸���

		pcap_freealldevs(alldevs); // ��� ��ġ�� �������ص�
		return -1; // �����մϴ�.
	}

	//������ �������̽����� �̵��մϴ�.
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	//����͸� ���ϴ�.
	if ((adhandle = pcap_open_live(d->name,  // name of the device
		65536,     // portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL   // remote authentication
	)) == NULL)
	{ // ���� ������ ����ٸ�
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n"); // �����޼����� ����ϰ� 
		
		pcap_freealldevs(alldevs); // ��� ��ġ�� �������ص�
		return -1; // �����մϴ�.
	}

	//�� �������� ��� ��ġ�� �������ݴϴ�.
	pcap_freealldevs(alldevs);

	//ĸ�ĸ� �����մϴ�.
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	//�̴��� Ÿ���� �̽��ϴ�.
	u_short Ether_type = ntohs(*((u_short*)(pkt_data + 12)));

	//IP ����� �����մϴ�.
	IP_HDR * iph = (IP_HDR*)(pkt_data + 14);

	//�̴��� Ÿ���� IP���
	if (Ether_type == 0x800) {

		//Destination MAC�� ����մϴ�.
		printf("Destination MAC : ");
		for (int i = 0; i < 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 5)));

		//Source MAC�� ����մϴ�.
		printf("Source MAC : ");
		for (int i = 6; i < 6 + 5; i++)
			printf("%02X-", *((u_char*)(pkt_data + i)));
		printf("%02X    ", *((u_char*)(pkt_data + 6 + 5)));
		
		//������ ���� �̴��� Ÿ���� ������ݴϴ�.
		printf("\nEther Type : 0x%04X (%s)\n", Ether_type, (Ether_type == 0x0800) ? "IP" : "ARP");

		//IP ����� ���� �������� ������ݴϴ�.
		printf("IP ver : 0x%02X \t IP len : %4d \t Pkt Id : %4d\n", iph->ipver, ntohs(iph->ihl), ntohs(iph->pkt_id));
		printf("TTL : %3d \t Protocol : 0x%02X (%s) \n", iph->ttl, iph->protocol, (iph->protocol == 0x06) ? "TCP":"UDP");

		//Source IP�� Destination IP�� ����մϴ�.
		printf("SIP : %d.%d.%d.%d    ", iph->sip[0], iph->sip[1], iph->sip[2], iph->sip[3]);
		printf("DIP : %d.%d.%d.%d\n", iph->dip[0], iph->dip[1], iph->dip[2], iph->dip[3]);

		//Source Port�� Destination Port�� ������ ������ �����
		u_short sport = ntohs((u_short)(iph->payload));
		u_short dport = ntohs(*(((u_short*)&iph->payload) + 1));

		//Source Port�� Destination Port�� ����մϴ�.
		printf("SPort : %d", sport);
		printf("    DPort : %d",dport);

		//�� ��Ŷ�� ���� ����� ��� �����ٸ� �ι� �������ݴϴ�.
		printf("\n\n");
	}

	
}