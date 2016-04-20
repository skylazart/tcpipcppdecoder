#ifndef OBSERVERS_H
#define OBSERVERS_H

#include <vector>
#include <memory>

class Observer {
public:   
    Observer() {

    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	observers_.push_back(lp);
    }

    void iterate(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header, const u_char* packet) {

	for (std::shared_ptr<LayerParser> observer: observers_) {
	    if ((*observer).match(offset, layers_data, header, packet)) {
		(*observer).process(offset, layers_data, header, packet);
	    }
	}
    }
    
private:
    std::vector<std::shared_ptr<LayerParser>> observers_;
};


#endif /* OBSERVERS_H */
