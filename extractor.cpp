#include "extractor.h"

std::string get_mac_address(uint8_t* mac_address) {
    char res[18] = {' ', };
    sprintf(res, "%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
    std::string ret = res;
    return ret;
}

std::string get_ip_address(in_addr ip_address) {
    char res[16] = {' ', };
    sprintf(res, "%-15s", inet_ntoa(ip_address));
    std::string ret = res;
    return ret;
}

std::string get_port_number(uint16_t port_number) {
    char res[6] = {' ', };
    sprintf(res, "%05d", ntohs(port_number));
    std::string ret = res;
    return ret;
}

std::string get_sample_data(uint8_t* payload, uint8_t len) {
    char res[49] = {' ', };
    for (int i = 0 ; i < 16 && i < len ; i++) {
        if (i != 7) sprintf(&res[i*3], "%02x ", payload[i]);
        else sprintf(&res[i*3], "%02x\n", payload[i]);
    }
    std::string ret = res;
    return ret;
}
