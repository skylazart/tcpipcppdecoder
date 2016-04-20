#ifndef UDP_DATA_H
#define UDP_DATA_H

#include <string>
#include <sstream>
#include <cstring>
#include <netinet/in.h>

#include "util.hpp"

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
};
 
struct udp_data : public layer_data {
public:
    udp_data(udp_header* header) {
	std::memcpy(&udp_header_, header, sizeof(udp_header));
	udp_header_.src_port = ntohs(udp_header_.src_port);
	udp_header_.dst_port = ntohs(udp_header_.dst_port);
	udp_header_.len = ntohs(udp_header_.len);
    }

public:
    std::string to_string() {
	std::stringstream str;
	str << std::dec 
	    << "SRC PORT: " << udp_header_.src_port << " "
	    << "DST PORT: " << udp_header_.dst_port << " "
	    << "LEN: " << udp_header_.len;

	return str.str();
    }

public:
    udp_header get_header() {
	return udp_header_;
    }

    uint16_t get_src_port() {
	return udp_header_.src_port;
    }

    uint16_t get_dst_port() {
	return udp_header_.dst_port;
    }

private:
    udp_header udp_header_;
};

#endif /* UDP_DATA_H */
