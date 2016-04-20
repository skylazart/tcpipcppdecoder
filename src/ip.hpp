#ifndef IP_H
#define IP_H

#include <iomanip>
#include <memory>
#include <cstring>

#include "ip_data.hpp"

#define IPv4 0x4

class Ip: public LayerParser, public Observer {
public:
    Ip() {
	
    }

public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	return ((packet[offset] & 0xF0) >> 4) == IPv4;
    }
    

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {

	ip_header iph;
	std::memcpy(&iph, packet + offset, sizeof(ip_header));

	ip_data* ipdata = new ip_data(&iph);
	layers_data.push_back(layer_data_ptr(ipdata));

	/*
	std::cout << "Version: " << (int) iph.version() << " " 
		  << "Len: " << (int) iph.len() << " "
		  << "Total Len: " << (int) iph.total_length << " " 
		  << "Protocol: " << (int) iph.protocol
		  << std::endl;	
	*/

	std::cout << "IP PROTOCOL: " 
		  << ipdata->to_string() << std::endl;

	Observer::iterate(offset + iph.len(), layers_data, header, packet);
    }

    void summary() {
	// Nothing to do here
    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }

};

#endif /* IP_H */
