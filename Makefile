CC = g++
LNK = -lpcap -L./ -lCFFEXtraderapi -lssl -lcrypt  #-lc #-lssl -lcrypto -lc #
#CFLAG = -Wall
CFLAG = 

all: parse_pcap

parse_pcap: parse_pcap.o
	$(CC) parse_pcap.o $(CFLAG) $(LNK) -o parse_pcap

parse_pcap.o: parse_pcap.cpp kewei.h
	$(CC) -c parse_pcap.cpp -o parse_pcap.o

clean:
	rm parse_pcap parse_pcap.o
