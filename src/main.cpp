#include <iostream>
#include <memory>
#include <unistd.h>
#include <string.h>

#include "pcap.hpp"
#include "ethernet.hpp"
#include "ip.hpp"
#include "icmp.hpp"
#include "tcp.hpp"
#include "udp.hpp"
#include "data_dump.hpp"


void help(char * argv[]) {
    std::cout << "Usage: " << argv[0] << " [-d] <file1> [file2] ..."
	      << '\n'
	      << "   -d    enable debugging"
	      << std::endl;
    
}

int main(int argc, char *argv[]) {
    std::cout << "TCP/IP packet analyzer" << std::endl;
    
    int start_opts = 1;

    if (argc == 1) {
	help(argv);
	return -1;
    }

    Pcap pcap;

    LayerParser* ethernet = new Ethernet();
    LayerParser* ip = new Ip();
    LayerParser* icmp = new Icmp();
    LayerParser* tcp = new Tcp();
    LayerParser* udp = new Udp();
    LayerParser* data_dump = new DataDump();
    
    std::shared_ptr<LayerParser> ethernet_layer;
    std::shared_ptr<LayerParser> ip_layer;
    std::shared_ptr<LayerParser> icmp_layer;
    std::shared_ptr<LayerParser> tcp_layer;
    std::shared_ptr<LayerParser> udp_layer;
    std::shared_ptr<LayerParser> application_layer;

    ethernet_layer.reset(ethernet);
    ip_layer.reset(ip);
    icmp_layer.reset(icmp);
    tcp_layer.reset(tcp);
    udp_layer.reset(udp);
    application_layer.reset(data_dump);

    ethernet->register_observer(ip_layer);
    ip->register_observer(icmp_layer);
    ip->register_observer(tcp_layer);
    ip->register_observer(udp_layer);

    if (strcmp(argv[1], "-d") == 0) {
	tcp->register_observer(application_layer);
	start_opts = 2;
    }

    pcap.register_observer(ethernet_layer);
    

    // Analyzing the files
    for (int i = start_opts; i < argc; i++) {
	if (!pcap.analyze(argv[i])) {
	    std::cout << "Error processing: " << pcap.get_error() 
		      << std::endl;
	}
    }
    
    // Writing the summary
    ethernet->summary();
    ip->summary();
    tcp->summary();
    udp->summary();
    icmp->summary();

    return 0;
}
