#ifndef TCP_H
#define TCP_H

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

#include "tcp_session.hpp"

class Tcp : public LayerParser, public Observer, public Report {
public:
    Tcp() {

    }

public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& ip_layer_data = *it;
	ip_data& ip = (ip_data&)*ip_layer_data;

	// Looking for the protocol specicied by ip header
	return ip.get_protocol() == 6;
    }

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {
	tcp_header tcph;
	std::memcpy(&tcph, packet + offset, sizeof(tcp_header));
	
	tcp_data* tcpdata = new tcp_data(&tcph);
	layers_data.push_back(layer_data_ptr(tcpdata));

	std::cout << "TCP PROTOCOL: " 
		  << tcpdata->to_string() << std::endl;

	tcp_session.update(layers_data);

	Observer::iterate(offset + tcpdata->get_doff(), 
			  layers_data, header, packet);
    }

    void summary() {
	// Print the ports filtered
	tcp_session.summary();
    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }    


private:
    tcp_session::TcpSession tcp_session;
};

#endif /* TCP_H */
