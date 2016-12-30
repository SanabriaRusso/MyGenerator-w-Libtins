#include <tins/tins.h>
#include <sys/time.h>
#include <vector>
#include <tins/tcp_ip/stream_follower.h>
#include "sniffer_helpers.h"

using namespace Tins;
using namespace std;

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

class Press 
{
	public:
		void showMe(Packet &p)
		{
			cout << "--->[" << p.timestamp().seconds() << "] Source IP: " <<
				p.pdu()->rfind_pdu<IP>().src_addr() << ", Destination IP: " <<
				p.pdu()->rfind_pdu<IP>().dst_addr() << endl;
		}

};


int main() 
{
	//Initialization
	BasicHelper exp;

	//pcap filter
	const string filter = "net 193.168.168.0 mask 255.255.255.0 and ((udp dst portrange 9000-9999 and udp dst portrange 19000-19999) or icmp)";
	exp.set_filter(filter);

	const string iface = "eth1";
	Sniffer sniffer(iface, exp.get_sniffer_conf());

	cout << "Ready to sniff: " << iface << endl;

	//BasicProcessor processor;
	MultiFlowProcessor processor;
	sniffer.sniff_loop(processor);

	return 0;
}
