#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include "extractor.h"

void print_divider(std::string title) {
    printf("---------------");
    printf("%s", title.c_str());
    printf("---------------\n");
}

void usage() {
    printf("ERROR: Please enter your interface\n");
    printf("\n");
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("INFO: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* ethernet_header = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_hl << 2));

        if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) continue;
        if (ip_header->ip_p != IPPROTO_TCP) continue;

        uint8_t* payload = (uint8_t*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header->ip_hl*4 + tcp_header->th_off*4);
        uint8_t len = ntohs(ip_header->ip_len) - (ip_header->ip_hl*4 + tcp_header->th_off*4);
    
        printf("[           %04ubytes           ]\n", header->caplen);

        print_divider("SRC");
        printf("MAC  = %s\n", get_mac_address(ethernet_header->ether_shost).c_str());
        printf("IP   = %s\n", get_ip_address(ip_header->ip_src).c_str());
        printf("PORT = %s\n", get_port_number(tcp_header->th_sport).c_str());

        print_divider("DST");
        printf("MAC  = %s\n", get_mac_address(ethernet_header->ether_dhost).c_str());
        printf("IP   = %s\n", get_ip_address(ip_header->ip_dst).c_str());
        printf("PORT = %s\n", get_port_number(tcp_header->th_dport).c_str());

        print_divider("DAT");
        printf("%s", get_sample_data(payload, len).c_str());

        printf("\n\n\n");
    }
    printf("INFO: Stop Program...\n");

    pcap_close(handle);
}
