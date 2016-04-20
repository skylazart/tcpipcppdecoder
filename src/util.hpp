#ifndef mUTIL_H
#define mUTIL_H

#include <string>
#include <array>
#include <sstream>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace util {
    std::string parse_mac(std::array<u_char, 6>& raw);
    std::string network_ip_to_string(uint32_t address);
    
    bool is_ack(uint8_t flags);   
    bool is_fin(uint8_t flags);
    bool is_syn(uint8_t flags);
    bool is_rst(uint8_t flags);
    bool is_psh(uint8_t flags);
    bool is_request(uint8_t flags);

    
    std::string tcp_flags_to_str(uint8_t flags);
    std::string icmp_type_to_str(uint8_t type);
    std::string icmp_code_to_str(uint8_t type, uint8_t code);

    void hexdump(const u_char* ptr, int buflen);
};

#endif /* UTIL_H */
