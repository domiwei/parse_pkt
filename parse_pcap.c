#include <stdio.h>
#include <pcap.h>

int main(void)
{
	char *tcpdump_filename = "traffic";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header = NULL;
	const u_char *packet = NULL;
	long long pkg_count = 0;


	pcap_t *handler = pcap_open_offline(tcpdump_filename, errbuf);
	while (pcap_next_ex(handler, &header, &packet) >= 0) {
		printf("pkg %lld: pkt size = %d\n", pkg_count++, header->len);
	}

	pcap_close(handler);
	
}

