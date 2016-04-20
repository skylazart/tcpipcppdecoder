#ifndef TCP_SESSION_H
#define TCP_SESSION_H

#include <vector>
#include <unordered_map>

#include "layer_data.hpp"
#include "ip_data.hpp"
#include "tcp_data.hpp"
#include "report.hpp"

namespace tcp_session {
    enum tcp_state {
	SYN_SENT,
	ESTABLISHED,
	TERMINATED_NO_DATA,
	TERMINATED_WITH_DATA,
	REFUSED
    };
    
    struct session_attr {
	tcp_state state;
    };

    class TcpSession : public Report {
    public:
	TcpSession() : session_map_{} {
	}
	
    public:
	void update(std::vector<layer_data_ptr>& layers_data);
	void summary();

    private:
	void print_filterd_ports();
	std::string make_key(ip_data& ip, tcp_data& tcp);
	
    private:
	std::unordered_map<std::string, session_attr> session_map_;
    };    
};

#endif /* TCP_SESSION_H */
