#ifndef TCP_DATA_H
#define TCP_DATA_H

#include <string>
#include <sstream>
#include <cstring>
#include <netinet/in.h>

#include "util.hpp"

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;

    uint32_t seq;
    uint32_t ack_seq;

    uint8_t doffres1;
    
    uint8_t flags;

    uint16_t	window;
    uint16_t	checksum;
};

struct tcp_data : public layer_data {
public:
    tcp_data(tcp_header* header) {
	std::memcpy(&tcp_header_, header, sizeof(tcp_header));
	tcp_header_.src_port = ntohs(tcp_header_.src_port);
	tcp_header_.dst_port = ntohs(tcp_header_.dst_port);
    }

public:
    std::string to_string() {
	std::stringstream str;
	
	str << std::boolalpha
	    << "SRC PORT: " << tcp_header_.src_port << " "
	    << "DST PORT: " << tcp_header_.dst_port << " "
	    << "FLAGS: " << util::tcp_flags_to_str(tcp_header_.flags) << " "
	    << "REQUEST: " << util::is_request(tcp_header_.flags);

	return str.str();
    }

public:
    tcp_header get_tcpheader() {
	return tcp_header_;
    }

    uint16_t get_src_port() {
	return tcp_header_.src_port;
    }

    uint16_t get_dst_port() {
	return tcp_header_.dst_port;
    }
    
    uint8_t get_flags() {
	return tcp_header_.flags;
    }

    uint8_t get_doff() {
	return ((tcp_header_.doffres1 & 0xF0) >> 4) * 4;
    }

private:
    tcp_header tcp_header_;
};

#endif /* TCP_DATA_H */
