#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/ssl.h>

#include "pkt_header.h"
//#include "CFFEXtraderapi.h"

int parse_pkt_addr(const u_char *packet, const SniffIp **ip_addr,
		const SniffTcp **tcp_addr, const u_char **payload_addr)
{
	int ret = 0;
	SniffEthernet *ethernet = NULL;
	u_int size_ip, size_tcp;

	ethernet = (SniffEthernet *)(packet);
	*ip_addr = (SniffIp*)(packet + sizeof(SniffEthernet));
	size_ip = IP_HL(*ip_addr)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		ret = -EINVAL;
		goto out;
	}
	printf("source ip: %s, ", inet_ntoa((*ip_addr)->ip_src));
	printf("target ip: %s---", inet_ntoa((*ip_addr)->ip_dst));

	*tcp_addr = (SniffTcp *)(packet + sizeof(SniffEthernet) + size_ip);
	size_tcp = TH_OFF(*tcp_addr)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		ret = -EINVAL;
		goto out;
	}
	*payload_addr = (u_char *)(packet + sizeof(SniffEthernet) + size_ip + size_tcp);
out:
	return ret;
}

void print_payload(const u_char *packet, int len)
{
	int i;
	int count = 0;

	for (i = 0; i < len; i++) {
		printf("%02x ", *(packet + i));
		if (((++count) & 15) == 0)
			printf("\n");
	}
	printf("\n");
}

//extern class CFTDOrderField;
int main(void)
{
		/*
	const char *tcpdump_filename = "traffic";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header = NULL;
	const u_char *packet = NULL;
	long long pkg_count = 0;
	const SniffIp *ip_addr; // The IP header
	const SniffTcp *tcp_addr; // The TCP header
	const u_char *payload_addr;

	pcap_t *handler = pcap_open_offline(tcpdump_filename, errbuf);
	if (!handler) {
		fprintf(stderr, "Need tcp dump file \"%s\"\n", tcpdump_filename);
		exit(-1);
	}
	while (pcap_next_ex(handler, &header, &packet) >= 0) {
		int payload_len;
		if (parse_pkt_addr(packet, &ip_addr, &tcp_addr, &payload_addr) < 0)
			break;
		payload_len = header->caplen - ((char *)payload_addr - (char *)packet);
		printf("pkg %lld: pkt size = %d, data len = %d\n", pkg_count++, header->caplen, payload_len);
		print_payload(payload_addr, payload_len);
	}
	pcap_close(handler);
	*/
	void *fh = NULL;
	void (*func)();
	printf("hahahaha\n");
	fh = dlopen("./libCFFEXtraderapi.so", RTLD_LAZY);
	printf("hahahaha\n");
	if (!fh) {
			printf("fail to open, %s\n", dlerror());
			exit(-1);
	}
	printf("haha");
	//dlerror();
	func = (void(*)())dlsym(fh,"CFtdcTraderApiImpl::OnRspQryOrder");
	if (func) {
			printf("yaya!\n");
	}

	dlclose(fh);

	//CFTDOrderField a;
}

