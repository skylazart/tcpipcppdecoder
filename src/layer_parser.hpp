#ifndef LAYER_PARSER_H
#define LAYER_PARSER_H

#include <vector>
#include <memory>

#include "layer_data.hpp"

class LayerParser {
public:
    /**
     * Check whether this packet matches with the layer implementation or not
     */
    virtual bool match(int offset, 
		       std::vector<layer_data_ptr>& layers_data,
		       struct pcap_pkthdr* header,
		       const u_char* packet) = 0;

    /**
     * Process the packet and keep and keep its state
     */
    virtual void process(int offset, 
			 std::vector<layer_data_ptr>& layers_data,
			 struct pcap_pkthdr* header,
			 const u_char* packet) = 0;

    /**
     * Register a observer interested in the next layer
     */
    virtual void register_observer(std::shared_ptr<LayerParser>& lp) = 0;

    /**
     * Print the report
     */
    virtual void summary() = 0;
};

#endif /* LAYER_PARSER_H */
