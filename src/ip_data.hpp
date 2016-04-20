#ifndef IP_DATA_H
#define IP_DATA_H

#include "util.hpp"

struct ip_header {
    uint8_t version_length;
    uint8_t tos;

    uint16_t total_length;
    uint16_t id;
    uint16_t flags;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    
    uint32_t   src;
    uint32_t   dst;

    uint8_t version() const {
	return (version_length & 0xF0) >> 4;
    }

    uint8_t len() const {
	return (version_length & 0x0F) * 4;
    }
};

struct ip_data : public layer_data {
public:
    ip_data(ip_header* header) {
	protocol_ = header->protocol;
	total_length_ = htons(header->total_length);
	header_length_ = (header->version_length & 0x0F) * 4;
	source_ip_ = util::network_ip_to_string(header->src);
	destination_ip_ = util::network_ip_to_string(header->dst);
    }

public:
    uint8_t get_protocol() {
	return protocol_;
    }

    uint16_t get_total_length() {
	return total_length_;
    }

    uint8_t get_header_length() {
	return header_length_;
    }

    std::string get_source_ip() {
	return source_ip_;
    }

    std::string get_destination_ip() {
	return destination_ip_;
    }

    
public:
    std::string to_string() {
	std::stringstream str;

	str << "SRC IP: " << source_ip_ << " "
	    << "DST IP: " << destination_ip_ << " " 
	    << "PROTO: " << (int) protocol_ << " "
	    << "HEADER LEN: " << (int) header_length_ << " "
	    << "TOTAL LEN: " << (int) total_length_;

	return str.str();
    }
    
private:
    uint8_t protocol_;
    uint16_t total_length_;
    uint8_t header_length_;
    std::string source_ip_;
    std::string destination_ip_;
};

#endif /* IP_DATA_H */
