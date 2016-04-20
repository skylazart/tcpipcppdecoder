#ifndef ETHERNET_DATA_H
#define ETHERNET_DATA_H

#include <stdio.h>
#include <string>
#include <sstream>
#include <iomanip>

#include "layer_data.hpp"
#include "util.hpp"

struct ethernet_header {
    unsigned char destination_mac[6];
    unsigned char source_mac[6];
    unsigned short type;
};


struct ethernet_data : public layer_data {
    ethernet_data(ethernet_header* header) {
	type_ = ntohs(header->type);

	std::array<u_char, 6> temp;
	for (int i = 0; i < 6; i++)
	    temp[i] = header->source_mac[i];

	source_mac_address_ = util::parse_mac(temp);
	
	for (int i = 0; i < 6; i++)
	    temp[i] = header->destination_mac[i];

	destination_mac_address_ = util::parse_mac(temp);
    }
    
public:    
    std::string to_string() {
	std::stringstream str;
	str << "SOURCE MAC ADDRESS:" << source_mac_address_ << " "
	    << "DESTINATION MAC ADDRESS:" << destination_mac_address_ << " "
	    << "Type: 0x" << std::hex << std::setfill('0') << std::setw(4)
	    << type_;
	
	return str.str();
    }

public:
    short get_type() {
	return type_;
    }

    std::string get_source_mac_address() {
	return source_mac_address_;
    }

    std::string get_destination_mac_address() {
	return destination_mac_address_;
    }
    
private:
    short type_;
    std::string destination_mac_address_;
    std::string source_mac_address_;
};

#endif /* ETHERNET_DATA_H */
