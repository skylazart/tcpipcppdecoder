#ifndef UDP_H
#define UDP_H

#include <iomanip>
#include <memory>
#include <cstring>
#include <unordered_map>

#include "layer_parser.hpp"
#include "observer.hpp"
#include "tcp_data.hpp"
#include "ip_data.hpp"
#include "layer_data.hpp"
#include "util.hpp"
#include "report.hpp"

class Udp : public LayerParser, public Observer, public Report {
public:
    Udp() {

    }

public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& ip_layer_data = *it;
	ip_data& ip = (ip_data&)*ip_layer_data;
	
	return ip.get_protocol() == 17;
    }

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {

	udp_header udph;
	std::memcpy(&udph, packet + offset, sizeof(udp_header));
	
	udp_data* udpdata = new udp_data(&udph);
	layers_data.push_back(layer_data_ptr(udpdata));

	std::cout << "UDP PROTOCOL: " 
		  << udpdata->to_string() << std::endl;
    }

    void summary() {

    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }    


};

#endif /* UDP_H */
