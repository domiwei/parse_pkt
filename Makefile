CC = g++
LNK = -ldl -lpcap -lssl -L. -lCFFEXtraderapi #-lc #-lssl -lcrypto -lc #
#CFLAG = -Wall
CFLAG = 

all: parse_pcap

parse_pcap: parse_pcap.cpp
	$(CC) parse_pcap.cpp $(CFLAG) $(LNK) -o parse_pcap

clean:
	rm parse_pcap
