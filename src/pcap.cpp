#include <iostream>
#include <iomanip>
#include <sstream>

#include "layer_data.hpp"
#include "pcap.hpp"

bool Pcap::analyze(char *fname) {    
    pcap_t * handler = pcap_open_offline(fname, errbuf_);
    if (!handler) {
	// Unable to open file.
	set_error();
	return false;
    }

    // Parse the file
    read_packet(handler);

    // Close pcap handler
    pcap_close(handler);
    return true;
}


void Pcap::read_packet(pcap_t *handler) {
    const u_char *packet;
    struct pcap_pkthdr header;
    int cnt = 0;
    
    // Parsing packet by packet
    while ((packet = pcap_next(handler, &header)) != NULL) {
	std::cout << "Reading packet " << std::dec << ++cnt << std::endl;

	std::vector<layer_data_ptr> layers_data;
	iterate(0, layers_data, &header, packet);

	std::cout << std::setfill('.') << std::setw(80) << "."  
		  << std::endl;
    }
}

