#include "icmp.hpp"

void Icmp::calculate_most_famous(std::vector<layer_data_ptr>& layers_data) {
    auto it = layers_data.end() - 1;
    std::shared_ptr<layer_data>& ip_layer_data = *it;
    ip_data& p = (ip_data&)*ip_layer_data;

    most_popular_.update(p.get_destination_ip());
}

/** 
 * Parse ICMP destination unreachable to detect close or filtered ports
 */
void Icmp::parse_dest_unreachable(int offset, 
				  std::vector<layer_data_ptr>& layers_data,
				  struct pcap_pkthdr* header, 
				  const u_char* packet, 
				  icmp_header& icmph) {
    
    
    offset += sizeof(icmp_header) + 4;
    
    // Reading ip header
    ip_header iph;
    std::memcpy(&iph, packet + offset, sizeof(ip_header));
    
    ip_data ipdata(&iph);
    if (ipdata.get_protocol() != 17) {
	// I am just interested in UDP packets
	return;
    }
    
    offset += iph.len();
    
    // Reading udp header
    udp_header udph;
    std::memcpy(&udph, packet + offset, sizeof(udp_header));
    udp_data udpdata(&udph);

    std::cout << "ICMP DATA "
	      << "IP: " << ipdata.to_string() << " "
	      << "UDP: " << udpdata.to_string()
	      << std::endl;
    
    if (icmph.type == 3 && icmph.code == 3) {
	// Port is closed
	std::cout << "UDP CLOSED: " 
		  << ipdata.get_destination_ip() << " " 
		  << udpdata.get_dst_port() << std::endl;

    } else if (icmph.type == 3 && 
	       (icmph.code == 0 || icmph.code == 1 ||
		icmph.code == 2 || icmph.code == 9 ||
		icmph.code == 10 || icmph.code == 13)) {
	// Filtered
	std::cout << "UDP FILTERED: " 
		  << ipdata.get_destination_ip() << " " 
		  << udpdata.get_dst_port() << std::endl;
    }
}
