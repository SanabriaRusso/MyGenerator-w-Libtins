#include <tins/tins.h>
#include <sys/time.h>
#include <vector>
#include <algorithm>
#include <tins/tcp_ip/stream_follower.h>

using namespace Tins;
using namespace std;

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

#define TERMINATION_THRESHOLD 10000
#define EXPERIMENT_GAP 9000

/*
########################################
Basic Sniffer Helper
########################################
*/


class BasicHelper
{
	//Contains the setup sequence of a basic experiment
	public:
		SnifferConfiguration get_sniffer_conf(void);
		void set_sniffer_conf(void);
		void set_filter(string);
		const string get_filter(void);
		BasicHelper();

	private:
		SnifferConfiguration s_conf;
		string filter;

};

BasicHelper::BasicHelper(void)
{
	set_sniffer_conf();
}

void
BasicHelper::set_filter(string f)
{
	filter = f;
}

const string
BasicHelper::get_filter(void)
{
	if (!filter.empty())
	{
		return filter;
	}else
	{
		const string r = "";
		return r;
	}

}

void 
BasicHelper::set_sniffer_conf(void)
{
	s_conf.set_filter(get_filter());
	s_conf.set_promisc_mode(true);
	s_conf.set_snap_len(1500); //bytes
}

SnifferConfiguration 
BasicHelper::get_sniffer_conf(void)
{
		return s_conf;
}



/*
########################################
Basic Processor
########################################
*/

class BasicProcessor 
{
	public:
		bool operator() (Packet &p);
		virtual bool UDP_segments(Packet &p);
		virtual bool ICMP_packets(Packet &p);
		virtual void add_segment(Packet &p);		
		virtual long int get_received_segments(void);
		virtual double get_throughput(void);
		BasicProcessor();

	private:
		vector<Packet> vt;
};

BasicProcessor::BasicProcessor(void){}

bool 
BasicProcessor::operator() (Packet &p) 
{
	if (p.pdu()->find_pdu<IP>())
	{
		if (p.pdu()->find_pdu<UDP>())
		{
			return UDP_segments(p);
		}else if(p.pdu()->find_pdu<ICMP>())
		{
			return ICMP_packets(p);
		}
	}
	return true;
}

bool 
BasicProcessor::UDP_segments(Packet &p)
{
	UDP *u = p.pdu()->find_pdu<UDP>();
	if(u->dport() >= TERMINATION_THRESHOLD)
	{
		double avg_throughput = get_throughput();
		cout << "Terminating. Destination port: " << u->dport();
		cout << ", average throughput: " << avg_throughput << " Mbps" << endl;
		return false;
	}else
	{
		add_segment(p);
		return true;
	}
}

bool 
BasicProcessor::ICMP_packets(Packet &p)
{
	//cout << "A ping from: " << p.pdu()->rfind_pdu<IP>().src_addr() << ", to: " <<
	//p.pdu()->rfind_pdu<IP>().dst_addr()	<< endl;
	return true;
}

void 
BasicProcessor::add_segment(Packet &p)
{
	vt.push_back(p);
}

long int 
BasicProcessor::get_received_segments(void)
{
	return vt.size();
}

double 
BasicProcessor::get_throughput(void)
{
	long int packets = get_received_segments();

	Packet dummy = vt.back();
	RawPDU raw = dummy.pdu()->rfind_pdu<RawPDU>();
	uint32_t payload = raw.payload_size();
	
	Packet dummy_front = vt.front();
			
	double diff = (dummy.timestamp().seconds() + (dummy.timestamp().microseconds() * 1e-6)) 
					- (dummy_front.timestamp().seconds() + (dummy_front.timestamp().microseconds() * 1e-6));

	double throughput = packets * payload * 8.0 / diff;

	cout << "First packet: " << dummy_front.timestamp().seconds() + 
								(dummy_front.timestamp().microseconds() * 1e-6) << endl;
	cout << "Last packet: " << (dummy.timestamp().seconds() + 
								(dummy.timestamp().microseconds() * 1e-6))  << endl;
	cout << "Experiment duration: " << diff << endl;
	cout << "Payload: " << payload << endl;
	cout << "Packets: " << packets << endl;

	return throughput;

}


/*
########################################
MultiFlow Processor
########################################
*/

struct flow_data
{
	IP *ip;
	UDP *udp;
	uint16_t termination_port;
	map<uint16_t, uint32_t> rx_bytes;
	map<uint16_t, uint32_t> rx_packets;
	double start, end;
};

class MultiFlowProcessor : public BasicProcessor
{
	public:
		bool UDP_segments(Packet &);
		bool termination(uint16_t, int, double);
		bool keep_sniffing(void);
		void get_throughput(struct flow_data &);

		double count;

	private:
		vector<struct flow_data> flows;
		vector<uint16_t> udp_ports;
};

bool 
MultiFlowProcessor::UDP_segments(Packet &p)
{
	uint16_t dport = p.pdu()->find_pdu<UDP>()->dport();

	if (dport < EXPERIMENT_GAP)
		return true;

	if (flows.empty())
	{
		goto fill_it_in;
	}else
	{	
		int num_flows = flows.size();
		if (dport >= TERMINATION_THRESHOLD)
		{
			vector<uint16_t>::iterator it = find(udp_ports.begin(), udp_ports.end(), abs(dport - TERMINATION_THRESHOLD));
			if (it != udp_ports.end())
			{
				double end_time = p.timestamp().seconds() + (p.timestamp().microseconds() * 1e-6);
				return termination(dport, num_flows, end_time);
			}else
			{
				return true;
			}
		}else
		{
			for (int i = 0; i < num_flows; i++)
			{
				if (flows.at(i).rx_packets.find(dport) != flows.at(i).rx_packets.end())
				{
					//registering metrics for the flow
					flows.at(i).rx_bytes[dport] += 
						(long double)(p.pdu()->rfind_pdu<RawPDU>().payload_size());
					flows.at(i).rx_packets[dport] += 1;
					return true;
				}
			}
		}
		goto fill_it_in;
	}

	fill_it_in:
		if ((find(udp_ports.begin(), udp_ports.end(), dport)) == udp_ports.end())
		{
			udp_ports.push_back(dport);

			struct flow_data f;
			f.udp = p.pdu()->find_pdu<UDP>();
			f.ip = p.pdu()->find_pdu<IP>();
			f.termination_port = dport + TERMINATION_THRESHOLD;
			f.start = p.timestamp().seconds() + (p.timestamp().microseconds() * 1e-6);
			f.rx_packets[dport] += 1;
			f.rx_bytes[dport] += (long double)(p.pdu()->rfind_pdu<RawPDU>().payload_size());

			flows.push_back(f);

			cout << "\nAdding new flow. Des port: " << dport << ", start time: " << f.start << endl;
			return true;
		}else
		{
			return true;
		}
}

bool
MultiFlowProcessor::termination(uint16_t dport, int num_flows, double end_time)
{
	for (int i = 0; i < num_flows; i++)
	{
		uint16_t t_port = flows.at(i).termination_port;
		if (dport == t_port)
		{
			flows.at(i).end = end_time;
			get_throughput(flows.at(i));
			flows.erase(flows.begin() + i);
			udp_ports.erase(remove(udp_ports.begin(), udp_ports.end(), dport), udp_ports.end());
			return keep_sniffing();
		}
	}
}

bool
MultiFlowProcessor::keep_sniffing(void)
{
	cout << "terminating: "  << flows.size() << endl << endl;
	if (flows.empty())
		return false;
	return true;
}

void
MultiFlowProcessor::get_throughput(struct flow_data &f)
{
	double diff = ceil(f.end - f.start);
	uint16_t port = f.termination_port - TERMINATION_THRESHOLD;
	double bits_rx = f.rx_bytes[port] * 8.0;
	double S = bits_rx / diff;

	cout << "Stream for destination port: " << port	<< " ended. Throughput: " << S << " Mbps" << endl;
	cout << "Number of received packets: " << f.rx_packets[port] << ", bytes: " << f.rx_bytes[port] << endl;
}
