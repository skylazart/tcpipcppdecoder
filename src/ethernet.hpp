#ifndef ETHERNET_H
#define ETHERNET_H

#include <vector>
#include <string>
#include <memory>

#include <string.h>

#include "layer_data.hpp"
#include "ethernet_data.hpp"
#include "layer_parser.hpp"
#include "observer.hpp"
#include "report.hpp"

class Ethernet : public LayerParser, public Observer, public Report {
public:
    Ethernet() {

    }
    
public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	/* TODO: I am assuming it is ethernet. */ 
	return true;
    }
    

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {

	ethernet_header eth_header;
	memcpy(&eth_header, packet + offset, sizeof(ethernet_header));	
	ethernet_data* edata = new ethernet_data(&eth_header);

	layers_data.push_back(layer_data_ptr(edata));

	std::cout << "ETHERNET LAYER: " 
		  << edata->to_string() << std::endl;
	
	Observer::iterate(offset + 14, layers_data, header, packet);
    }

    void summary() {
	// Nothing to do here
    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }
};


#endif /* ETHERNET_H */
