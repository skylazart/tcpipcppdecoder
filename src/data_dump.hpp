#ifndef HTTP_H
#define HTTP_H

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


class DataDump : public LayerParser, public Observer, public Report {
public:
    DataDump() {

    }

public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& tcp_layer_data = *it;
	tcp_data& tcp = (tcp_data&)*tcp_layer_data;

	return (tcp.get_src_port() == 80 || tcp.get_dst_port() == 80 ||
		tcp.get_src_port() == 21 || tcp.get_dst_port() == 21);
    }

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {
	
	if (layers_data.size() != 3) return;

	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& tcp_layer_data = *it;
	std::shared_ptr<layer_data>& ip_layer_data = *(--it);

	tcp_data& tcpdata = (tcp_data&)*tcp_layer_data;
	ip_data& ipdata = (ip_data&)*ip_layer_data;

	uint8_t flags = tcpdata.get_flags();

	if (!(util::is_psh(flags) && util::is_ack(flags)))
	    return;

	int data_len = 
	    ipdata.get_total_length() - 
	    (ipdata.get_header_length() + tcpdata.get_doff());

	util::hexdump((packet + offset), data_len);
    }

    void summary() {

    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }    

};

#endif /* HTTP_H */
