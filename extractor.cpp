#include "extractor.h"

std::string get_mac_address(uint8_t* macAddress) {
    char res[18] = {' ', };
    sprintf(res, "%02x:%02x:%02x:%02x:%02x:%02x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    std::string ret = res;
    return ret;
}

std::string get_ip_address(in_addr ipAddress) {
    char res[16] = {' ', };
    sprintf(res, "%-15s", inet_ntoa(ipAddress));
    std::string ret = res;
    return ret;
}

std::string get_port_number(uint16_t portNumber) {
    char res[6] = {' ', };
    sprintf(res, "%05d", ntohs(portNumber));
    std::string ret = res;
    return ret;
}

std::string get_sample_data(uint8_t* payload, uint8_t length) {
    char res[49] = {' ', };
    int sampleLength = 16<length ? 16 : length;
    for (int i = 0 ; i < sampleLength ; i++) {
        if (i != 7) sprintf(&res[i*3], "%02x ", payload[i]);
        else sprintf(&res[i*3], "%02x\n", payload[i]);
    }
    std::string ret = res;
    return ret;
}
