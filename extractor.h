#ifndef EXTRACTOR_H
#define EXTRACTOR_H

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>

std::string get_mac_address(uint8_t* mac_address);
std::string get_ip_address(struct in_addr ip_address);
std::string get_port_number(uint16_t port_number);
std::string get_sample_data(uint8_t* payload, uint8_t len);

#endif // EXTRACTOR_H
