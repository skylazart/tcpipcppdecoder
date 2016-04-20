#include <iostream>
#include <sstream>
#include <memory>

#include "tcp_session.hpp"
#include "tcp_data.hpp"
#include "ip_data.hpp"
#include "util.hpp"

namespace tcp_session {
    void TcpSession::update(std::vector<layer_data_ptr>& layers_data) {
	if (layers_data.size() != 3) return;

	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& tcp_layer_data = *it;
	std::shared_ptr<layer_data>& ip_layer_data = *(--it);

	tcp_data& tcp = (tcp_data&)*tcp_layer_data;
	ip_data& ip = (ip_data&)*ip_layer_data;

	std::string key = make_key(ip, tcp);
	
	uint8_t flags = tcp.get_flags();

	if (util::is_syn(flags) && !util::is_ack(flags)) {
	    // SYN SENT
	    session_map_.insert(std::pair<std::string, session_attr>
				(key, session_attr{SYN_SENT}));

	} else 	if (util::is_syn(flags) && util::is_ack(flags)) {
	    auto it = session_map_.find(key);

	    if (it == session_map_.end()) {
		// Probably a illegal state (syn ack without syn)
		return;
	    }

	    // Session found
	    std::cout << "TCP OPEN: "
		      << ip.get_source_ip() << " " 
		      << tcp.get_src_port() << std::endl;

	    it->second.state = ESTABLISHED;

	} else if (util::is_rst(flags) && util::is_ack(flags)) {
	    auto it = session_map_.find(key);

	    if (it == session_map_.end())
		return;
	    
	    if (it->second.state == SYN_SENT) {
		// RST just after SYN means connection rejected (port closed)
		it->second.state = REFUSED;

		std::cout << "TCP CLOSED: " 
			  << ip.get_source_ip() << " " 
			  << tcp.get_src_port() << std::endl;

	    } else if (it->second.state == ESTABLISHED) {
		// Connection closed
		it->second.state = TERMINATED_NO_DATA;

		std::cout << "Terminated "
			  << ip.to_string() << " " 
			  << tcp.to_string() << std::endl;
	    }
	}
    }

    /* 
     * Create the key using src/dst ip and ports but considering 
     * the direction.
     * TODO: check if it is the better option
     */
    std::string TcpSession::make_key(ip_data& ip, tcp_data& tcp) {
	std::stringstream str;

	uint16_t flags = tcp.get_flags();

	// Detecting the direction
	if (util::is_request(flags)) {
	    str << ip.get_source_ip() << ":" << tcp.get_src_port()<<" "
		<< ip.get_destination_ip() << ":" << tcp.get_dst_port();
	} else {
	    str << ip.get_destination_ip() << ":" << tcp.get_dst_port()<<" "
		<< ip.get_source_ip() << ":" << tcp.get_src_port();
		
	}
	
	return str.str();	    
    }

    void TcpSession::summary() {
	print_filterd_ports();
    }

    void TcpSession::print_filterd_ports() {
	/* Because we are maintaining the data in map even after connection 
	 * finished, this task to find the filtered ports will cost O(n).
	 * Should not be used during the packet processing.
	 */
	
	int total_of_connections = 0;

	for (auto it = session_map_.begin(); it != session_map_.end(); it++) {
	    if (it->second.state == SYN_SENT) {
		std::cout << "TCP FILTERED: " 
			  << it->first << std::endl;
	    } else if (it->second.state != REFUSED) {
		// Couting valid established connections
		total_of_connections++;
	    }
	}

	std::cout << "TCP total connections: " << total_of_connections 
		  << " (successfully established)"
		  << std::endl;
    }
};
