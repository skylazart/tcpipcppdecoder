#ifndef PCAP_H
#define PCAP_H

#include <pcap/pcap.h>
#include <string>
#include <vector>

#include "layer_parser.hpp"
#include "observer.hpp"


class Pcap : public Observer {
public:
    Pcap() : in_error_{false}, observers_{} {
	
    }

public:
    bool analyze(char *fname);
    
    char * get_error() {
	if (!in_error_) {
	    return nullptr;
	}
	
	return errbuf_;
    }

    

private:
    void set_error() {
	in_error_ = true;
    }
    
    void read_packet(pcap_t *handler);
    
private:
    bool in_error_;
    std::vector<LayerParser*> observers_;    
    char errbuf_[PCAP_ERRBUF_SIZE];
};

#endif /* PCAP_H */
