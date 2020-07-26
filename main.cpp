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

void print_data(std::string title, const u_char* packet, uint8_t ipLen, uint8_t ipHeaderLen, uint8_t tcpOffset) {
    uint8_t* payload = (uint8_t*)(packet + sizeof(struct libnet_ethernet_hdr) + ipHeaderLen + tcpOffset);
    uint8_t length = ntohs(ipLen) - (ipHeaderLen + tcpOffset);

    print_divider(title);

    printf("%s", get_sample_data(payload, length).c_str());
}

void print_information(std::string title, uint8_t* mac, in_addr ip, uint16_t port) {
    print_divider(title);

    printf("MAC  = %s\n", get_mac_address(mac).c_str());
    printf("IP   = %s\n", get_ip_address(ip).c_str());
    printf("PORT = %s\n", get_port_number(port).c_str());
}

void print_title(uint8_t packetLen) {
    printf("[           %04ubytes           ]\n", packetLen);
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

        struct libnet_ethernet_hdr* ethernetHeader = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipHeader = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcpHeader = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ipHeader->ip_hl << 2));

        if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP) continue;
        if (ipHeader->ip_p != IPPROTO_TCP) continue;
    
        print_title(header->caplen);

        print_information("SRC", ethernetHeader->ether_shost, ipHeader->ip_src, tcpHeader->th_sport);
        print_information("DST", ethernetHeader->ether_dhost, ipHeader->ip_dst, tcpHeader->th_dport);
        print_data("DAT", packet, ipHeader->ip_len, ipHeader->ip_hl*4 , tcpHeader->th_off*4);

        printf("\n\n\n");
    }
    printf("INFO: Stop Program...\n");

    pcap_close(handle);
}
