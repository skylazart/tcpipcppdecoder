#ifndef ICMP_H
#define ICMP_H

/**
 * TrustWave Challenge
 * by: Felipe Cerqueira (skylazart@gmail.com) 
 * Date: 14/Nov/2015
 */


/*
  https://nmap.org/book/man-port-scanning-techniques.html
  
  UDP  scan  works by  sending  a  UDP  packet to  every  targeted
  port.   For  some   common  ports   such   as  53   and  161,   a
  protocol-specific payload is sent  to increase response rate, but
  for  most   ports  the  packet   is  empty  unless   the  --data,
  --data-string, or --data-length options are specified. If an ICMP
  port unreachable error (type 3, code  3) is returned, the port is
  closed. Other ICMP unreachable errors (type  3, codes 0, 1, 2, 9,
  10, or  13) mark  the port as  filtered. Occasionally,  a service
  will respond  with a UDP packet,  proving that it is  open. If no
  response  is   received  after   retransmissions,  the   port  is
  classified as  open|filtered. This means  that the port  could be
  open,   or    perhaps   packet    filters   are    blocking   the
  communication.  Version  detection  (-sV)  can be  used  to  help
  differentiate the truly open ports from the filtered ones.  */


#include <iostream>
#include <iomanip>
#include <memory>
#include <cstring>
#include <array>
#include <unordered_map>

#include "layer_parser.hpp"
#include "observer.hpp"
#include "layer_data.hpp"
#include "icmp_data.hpp"
#include "udp_data.hpp"
#include "ip_data.hpp"
#include "report.hpp"
#include "most_popular.hpp"

class Icmp : public LayerParser, public Observer, public Report {
public:
    Icmp() {

    }


public:
    bool match(int offset, std::vector<layer_data_ptr>& layers_data,
	       struct pcap_pkthdr* header, const u_char* packet) {
	auto it = layers_data.end() - 1;
	std::shared_ptr<layer_data>& ip_layer_data = *it;
	ip_data& p = (ip_data&)*ip_layer_data;

	// Looking for the protocol specicied by ip header
	return p.get_protocol() == 1;
    }

    void process(int offset, std::vector<layer_data_ptr>& layers_data,
		 struct pcap_pkthdr* header,
		 const u_char* packet) {

	// Calculating the most famous ip addr receiving ICMP
	calculate_most_famous(layers_data);
	
	icmp_header icmph;
	std::memcpy(&icmph, packet + offset, sizeof(icmp_header));
	
	icmp_data* icmpdataptr = new icmp_data(&icmph);
	layers_data.push_back(layer_data_ptr(icmpdataptr));

	std::cout << "ICMP PROTOCOL: "
		  << icmpdataptr->to_string()
		  << std::endl;

	icmph = icmpdataptr->get_header();	
	if (icmph.type == 3) {
	    // Offset still poiting to icmp header beginning
	    parse_dest_unreachable(offset, layers_data, 
				   header, packet, icmph);
	}
    }

    void summary() {
	std::cout << "Most popular ip address for ICMP packets: "
		  << most_popular_.get_popular() << std::endl;
    }

    void register_observer(std::shared_ptr<LayerParser>& lp) {
	Observer::register_observer(lp);
    }    

private:
    void calculate_most_famous(std::vector<layer_data_ptr>& layers_data);
    
    void parse_dest_unreachable(int offset, 
				std::vector<layer_data_ptr>& layers_data,
				struct pcap_pkthdr* header, 
				const u_char* packet, 
				icmp_header& icmph);

private:
    MostPopular<std::string> most_popular_;
};

#endif /* ICMP_H */
