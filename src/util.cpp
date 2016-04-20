#include "util.hpp"

#include <vector>
#include <unordered_map>

namespace util {
    static const std::string UKNOWN_STR {"Uknown"};

    // Just some interesting icmp codes
    static const std::unordered_map<int, std::string> icmp_type_desc_map = {
	{0, "Echo Reply"},
	{3, "Destination Unreachable"},
	{5, "Redirect Message"},
	{8, "Echo Request"},
	{11, "Time-to-Live Exceeded"}
    };

    // Just some interesing icmp codes
    static const std::unordered_map<int, std::vector<std::string>> icmp_code_desc_map = {
	
	{0, {"Echo reply"}},	
	{3, {"Destination network unreachable",
	     "Destination host unreachable",
	     "Destination protocol unreachable",
	     "Destination port unreachable",
	     "Fragmentation required, and DF flag set",
	     "Source route failed",
	     "Destination network unknown",
	     "Destination host unknown",
	     "Source host isolated",
	     "Network administratively prohibited",
	     "Host administratively prohibited",
	     "Network unreachable for TOS",
	     "Host unreachable for TOS",
	     "Communication administratively prohibited",
	     "Host Precedence Violation",
	     "Precedence cutoff in effect"}},

	{5, {"Redirect Datagram for the Network",
	     "Redirect Datagram for the Host",
	     "Redirect Datagram for the TOS & network",
	     "Redirect Datagram for the TOS & host"}},
	
	{8, {"Echo request"}},
	{11, {"TTL expired in transit", 
	      "Fragment reassembly time exceeded"}}
	     
    };
    
    std::string parse_mac(std::array<u_char, 6>& raw) {
	std::stringstream str;
	str << std::uppercase << std::setfill('0') << std::setw(2) 
	    << std::hex
	    << (int)raw[0] << ":"
	    << (int)raw[1] << ":"
	    << (int)raw[2] << ":"
	    << (int)raw[3] << ":"
	    << (int)raw[4] << ":"
	    << (int)raw[5];
	    
	    
	return str.str();
    }    

    std::string network_ip_to_string(uint32_t address) {
	struct in_addr addr;
	addr.s_addr = address;
	char * p = inet_ntoa(addr);
	return std::string(p);
    }

    bool is_ack(uint8_t flags) {
	return (flags & 16) > 0;
    }
    
    bool is_fin(uint8_t flags) {
	return (flags & 1) > 0;
    }

    bool is_syn(uint8_t flags) {
	return (flags & 2) > 0;	
    }

    bool is_rst(uint8_t flags) {
	return (flags & 4) > 0;
    }

    bool is_psh(uint8_t flags) {
	return (flags & 8) > 0;
    }

    bool is_request(uint8_t flags) {
	if (flags == 1 || flags == 2 || flags == 4 || 
	    flags == 8 || flags == 16) {
	    return true;
	}
	
	return false;
    }
	    
    std::string tcp_flags_to_str(uint8_t flags) {
	std::stringstream str;
	
	if (is_fin(flags)) {
	    if (str.tellp() > 0)
		str << ", ";

	    str << "[FIN]";
	}

	if (is_ack(flags)) {
	    if (str.tellp() > 0)
		str << ", ";

	    str << "[ACK]";
	}

	if (is_syn(flags)) {
	    if (str.tellp() > 0)
		str << ", ";

	    str << "[SYN]";
	}

	if (is_rst(flags)) {
	    if (str.tellp() > 0)
		str << ", ";

	    str << "[RST]";
	}

	if (is_psh(flags)) {
	    if (str.tellp() > 0)
		str << ", ";

	    str << "[PSH]";
	}

	return str.str();
    }

    std::string icmp_type_to_str(uint8_t type) {
	auto it = icmp_type_desc_map.find(type);
	if (it == icmp_type_desc_map.end()) {
	    return UKNOWN_STR;
	}
	
	return it->second;
    }

    std::string icmp_code_to_str(uint8_t type, uint8_t code) {
	auto it = icmp_code_desc_map.find(type);
	if (it == icmp_code_desc_map.end()) {
	    return UKNOWN_STR;
	}

	if (code > it->second.size()) {
	    return UKNOWN_STR;
	}

	return it->second[code];
    }   


    void hexdump(const u_char* ptr, int buflen) {
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;

	for (i=0; i<buflen; i+=16) {
	    printf("%06x: ", i);
	    for (j=0; j<16; j++) {
		if (i+j < buflen) {
		    printf("%02x ", buf[i+j]);
		} else {
		    printf("   ");
		}
	    }

	    printf(" ");

	    for (j=0; j<16; j++) {
		if (i+j < buflen) {
		    printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		}
	    }
	    printf("\n");
	}
    }
};
