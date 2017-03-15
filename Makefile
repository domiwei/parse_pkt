CC = gcc
LNK = -lpcap

all: parse_pcap

parse_pcap: parse_pcap.c
	$(CC) parse_pcap.c $(LNK) -o parse_pcap

clean:
	rm parse_pcap
