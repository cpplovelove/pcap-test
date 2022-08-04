LDLIBS += -lpcap

all: 
	gcc -o pcap-test pcap-test.c -lpcap

clean:
	rm -f pcap-test *.o
