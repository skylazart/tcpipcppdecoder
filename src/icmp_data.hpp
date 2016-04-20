#ifndef ICMP_DATA_H
#define ICMP_DATA_H

#include <string>
#include <sstream>
#include <cstring>
#include <netinet/in.h>

#include "util.hpp"

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

struct icmp_data : public layer_data {
public:
    icmp_data(icmp_header* header) {
	std::memcpy(&icmp_header_, header, sizeof(icmp_header));
	icmp_header_.checksum = ntohs(icmp_header_.checksum);
    }

public:
    std::string to_string() {	
	std::stringstream str;
	str << std::hex << std::setw(4) << std::setfill('0')
	    << "TYPE: " 
	    << util::icmp_type_to_str(icmp_header_.type) << " "
	    << "CODE: " 
	    << util::icmp_code_to_str(icmp_header_.type, icmp_header_.code) << " "
	    << "CHKSUM: 0x" 
	    << icmp_header_.checksum;
	    
	return str.str();
    }

public:
    icmp_header get_header() {
	return icmp_header_;
    }

private:
    struct icmp_header icmp_header_;
};

#endif /* ICMP_DATA_H */
