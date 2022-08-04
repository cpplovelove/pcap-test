#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		
		//ethernet header
		struct libnet_ethernet_hdr *eth;
		struct libnet_ipv4_hdr *ip;
		struct libnet_tcp_hdr *tcp;
		eth = (struct libnet_ethernet_hdr *)packet;
		//ip header
		packet +=sizeof(struct libnet_ethernet_hdr);
		ip = (struct libnet_ipv4_hdr *)packet;
		//tcp header
		packet +=sizeof(struct libnet_ipv4_hdr);
		tcp =(struct libnet_tcp_hdr *)packet;
		//data 
		packet +=sizeof(struct libnet_tcp_hdr);
		
		
		if(eth != NULL && ip!=NULL && tcp!=NULL){ 
			uint8_t isTcp = ip-> ip_p;
			if(isTcp == 6){			
				//ethernet src mac
				int i=0;
				printf("ethernet src mac: ");
				for(int i=0;i<ETHER_ADDR_LEN;i++){
					printf("%02x",eth->ether_shost[i]);
					if(i!=ETHER_ADDR_LEN-1) printf(":");
				}
				//ethernet dst mac
				printf("\nethernet dst mac: ");
				for(int i=0;i<ETHER_ADDR_LEN;i++){
					printf("%02x",eth->ether_dhost[i]);
					if(i!=ETHER_ADDR_LEN-1) printf(":");
				}
		
				//ip
				printf("\nsrc ip : %s\n", inet_ntoa(ip->ip_src));
				printf("dst ip : %s\n", inet_ntoa(ip->ip_dst));
		
				//tcp
				printf("src port : %d\n", ntohs(tcp->th_sport));
				printf("dst port : %d\n", ntohs(tcp->th_dport));
		
				//data
				i=0;
				printf("data: ");
				if(packet[i]==NULL) printf("No Data\n\n");
				else {
					while(i< 10 && packet[i]!=NULL){
						printf("%02x ",packet[i]);
						i++;
					}
					printf("\n\n");
				}
			}
		}
	}

	pcap_close(pcap);
}


