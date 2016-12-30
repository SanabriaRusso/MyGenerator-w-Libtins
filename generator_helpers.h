#include <tins/tins.h>
#include <sys/time.h>
#include <vector>
#include <tins/tcp_ip/stream_follower.h>
#include <pthread.h>

using namespace Tins;
using namespace std;
using namespace std::placeholders;

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

#define TERMINATION_OFFSET 10000

/*
######################################################
Single CBR flows
######################################################
*/

struct global_settings
{
	string i_o;
	EthernetII eth;
	string dst_ip;
	string src_ip;
	double rate;
	uint16_t dst_udp, src_udp;
};

class CBRHelper 
{								
	//A Constant Bitrate generator object
	public:
		void set_basic_cbr_stream(void);
		void set_high_speed_cbr_stream(double);
		void set_high_speed_cbr_stream(struct global_settings);
		void setRate(double);
		double getRate(void);
		void setInterval(double);
		double getInterval(void);
		void setIfaceOut(const string&);
		void setDstMAC(const HWAddress<6>&);
		void setIPAddr(const string&, const string &);
		void setUDP(uint16_t, uint16_t);
		void encapsulateFrame(void);
		void fire(void);
		void fire_for_duration(double);
		void count_sent_packet(void);
		void count_sent_packet(double);
		long int get_sent_packets_count(void);
		double get_sent_bytes(void);
		void show_total_sent_packets(double);
		void show_total_sent_bytes(double);
		void signal_end_of_stream(void);
		void show_details(void);

		RawPDU* findRawPDU(void);
		IP* findIP(void);
		UDP* findUDP(void);
		UDP* findUDP(EthernetII*);
		string getIfOutName(void);
		HWAddress<6> getIfHwAddr(void);

		//constructors
		CBRHelper(void);
		CBRHelper(int);

	private:
		const uint8_t payload = 255;	// Bytes
		const int frame_size = 1470;	// Bytes

		double rate;					// Rate of the CBR in Mbps
		double duration;				// Duration of the flow in seconds
		double packet_interval;			// Interval between packets, needed to achieve rate


		NetworkInterface iface_out;		// Gateway interface towards destination
		NetworkInterface::Info info;	// Contains addressing information for iface_out

		EthernetII eth;

		//metrics
		long int packets_sent = 0;
		double	bytes_sent = 0;
};

CBRHelper::CBRHelper(void)
{
}

CBRHelper::CBRHelper(int exp_type)
{
	switch (exp_type)
	{
		case 1:
		default:
			set_basic_cbr_stream();
			break;
	}
}

void
CBRHelper::set_basic_cbr_stream(void)
{
	double r = 1e6;
	string i_o = "eth1";
	HWAddress<6> dst_mac("b8:27:eb:4a:6c:33");
	string dst_ip = "193.168.168.102";
	string src_ip = "193.168.168.1";
	uint16_t dst_port = 9999;
	uint16_t src_port = 11000;

	//Setting parameters for CBR object
	setRate(r);
	setInterval(getRate());

	//Interface and addressing
	setIfaceOut(i_o);
	
	setDstMAC(dst_mac);
	setIPAddr(dst_ip, src_ip);
	setUDP(dst_port, src_port);
	encapsulateFrame();
}

void
CBRHelper::set_high_speed_cbr_stream(double rate)
{
	set_basic_cbr_stream();
	setRate(rate);
	setInterval(getRate());
}

void
CBRHelper::set_high_speed_cbr_stream(struct global_settings settings)
{
	//Setting parameters for CBR object
	setRate(settings.rate);
	setInterval(getRate());

	//Interface and addressing
	setIfaceOut(settings.i_o);
	
	setDstMAC((HWAddress<6>)settings.eth.dst_addr());
	setIPAddr(settings.dst_ip, settings.src_ip);
	setUDP(settings.dst_udp, settings.src_udp);
	encapsulateFrame();
}

void 
CBRHelper::setRate(double r)
{
	if (r > 0)
		rate = r;
}

double
CBRHelper::getRate(void)
{
	return rate;
}

void 
CBRHelper::setInterval(double r)
{
	if (r > 0)
	{
		packet_interval = double((frame_size * 8) / r);
		packet_interval *= 1e6;
	}
}

double
CBRHelper::getInterval(void)
{
	return packet_interval;
}

void 
CBRHelper::setIfaceOut(const string &i)
{
	NetworkInterface iface(i);
	iface_out = iface;
	info = iface_out.addresses();
}

void 
CBRHelper::setDstMAC(const HWAddress<6> &m)
{
	eth.dst_addr(m);
	eth.src_addr(info.hw_addr);
}

void 
CBRHelper::setIPAddr(const string &dst, const string &src)
{
	eth /= IP(dst, src);
}

void 
CBRHelper::setUDP(uint16_t dst, uint16_t src)
{
	eth /= UDP(dst, src);
}


void 
CBRHelper::encapsulateFrame(void)
{
	eth /= RawPDU(&payload, frame_size);
}


RawPDU* 
CBRHelper::findRawPDU(void)
{
	return eth.find_pdu<RawPDU>();
}

IP*
CBRHelper::findIP(void)
{
	return eth.find_pdu<IP>();
}

UDP*
CBRHelper::findUDP(void)
{
	return eth.find_pdu<UDP>();
}


UDP* 
CBRHelper::findUDP(EthernetII *e)
{
	return e->find_pdu<UDP>();
}

string 
CBRHelper::getIfOutName(void)
{
	return iface_out.name();
}

HWAddress<6> 
CBRHelper::getIfHwAddr(void)
{
	return info.hw_addr;
}

void
CBRHelper::count_sent_packet(void)
{
	packets_sent+=1;
}

void
CBRHelper::count_sent_packet(double payload)
{
	packets_sent += 1;
	bytes_sent += payload;
}

long int 
CBRHelper::get_sent_packets_count(void)
{
	return packets_sent;
}

double
CBRHelper::get_sent_bytes(void)
{
	return bytes_sent;
}

void
CBRHelper::show_total_sent_packets(double diff)
{
	double rate = (get_sent_packets_count() * frame_size * 8.0) / diff;
	cout << "[" << diff << "s] Total sent packets: " << get_sent_packets_count() 
		<< ", generation rate: " << rate << " Mbps" << endl;
}

void
CBRHelper::show_total_sent_bytes(double diff)
{
	double rate = (get_sent_bytes() * 8.0) / diff;
	cout << "[" << diff << "s] Total sent packets: " << get_sent_packets_count() 
		<< " (" << get_sent_bytes() << " bytes), generation rate: " << rate << " Mbps" << endl;
}


void
CBRHelper::show_details(void)
{
	RawPDU *payload = findRawPDU();
	cout << "--->Payload: " << payload->payload_size() << endl;
		
	IP *ip = findIP();
	cout << "--->IP, src: " << ip->src_addr() << ", dst: " 
		<< ip->dst_addr() << endl;

	UDP *u = findUDP();
	cout << "--->UDP, destination: " << u->dport() << ", source: " << u->sport() << endl;
	
	cout << "--->Iface name: " << getIfOutName() <<
		", src MAC: " << getIfHwAddr() << endl;

	cout << endl;
}


void CBRHelper::signal_end_of_stream(void)
{
	EthernetII *closing = eth.clone();
	UDP *u = findUDP(closing);
	uint16_t dport = u->dport() + TERMINATION_OFFSET;
	u->dport(dport);

	PacketSender s;
	s.default_interface(iface_out);
	s.send(*closing);
}

void 
CBRHelper::fire(void)
{
	PacketSender s;
	s.default_interface(iface_out);

	vector<EthernetII> v;

	while (v.size() <= 10){
		s.send(eth);
		v.push_back(eth);
		usleep(getInterval());
	}
}

void
CBRHelper::fire_for_duration(double duration)
{
	PacketSender s;
	s.default_interface(iface_out);

	time_t start = time(NULL); //seconds since epoch

	RawPDU *payload = findRawPDU();
	double byte_load = payload->payload_size();

	while (time(NULL) - start < duration)
	{
		s.send(eth);
		count_sent_packet(byte_load);
		usleep(getInterval());
	}

	double diff = difftime(time(NULL), start);
	//show_total_sent_packets(diff);
	show_total_sent_bytes(diff);

	signal_end_of_stream();
}

/*
######################################################
Multiple CBR flows
######################################################
*/

struct thread_data
{
	double duration;
	int id = -1;
	CBRHelper *exp;
};

class MultipleCBRHelper : public CBRHelper
{
	public:
		void addFlow(struct global_settings);
		void multiple_fire_for_duration(double);

		//Thread catcher
		static void *gimme(void* arg);


		//constructors
		MultipleCBRHelper(void);

	private:
		vector<MultipleCBRHelper> flows;
};

MultipleCBRHelper::MultipleCBRHelper(void){}

void
MultipleCBRHelper::addFlow(struct global_settings s)
{

	MultipleCBRHelper exp;

	exp.set_high_speed_cbr_stream(s);
	exp.show_details();

	flows.push_back(exp);	
}

void 
MultipleCBRHelper::multiple_fire_for_duration(double duration)
{
	struct thread_data args[flows.size()];
	pthread_t threads[flows.size()];
	pthread_attr_t attr; //thread attributes
	void *status;

	// Initialize and set thread joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	int rc;
	for (int i = 0; i < flows.size(); i++)
	{
		args[i].id = i;
		args[i].duration = duration;
		args[i].exp = &flows.at(i);

		cout << "Creating a thread: " << i << endl;

		MultipleCBRHelper inst;
		rc = pthread_create(&threads[i], &attr, inst.gimme, (void *)&args[i]);

		if (rc)
		{
			cout << "Error: unable to create thread," << rc << endl;
         	exit(-1);	
		}
		usleep(1e6); //a second
	}

	// free attribute and wait for the other threads
	pthread_attr_destroy(&attr);

	for (int i = 0; i < flows.size(); i++)
	{
		rc = pthread_join(threads[i], &status);
		if (rc)
		{
			cout << "Error: unable to join thread, " << rc << endl;
			exit(-1);
		}
		cout << "Completed thread id: " << i << ", with status: " << status << endl;
	}

	pthread_exit(NULL);
}

void
*MultipleCBRHelper::gimme(void *args)
{
	struct thread_data *t_args;
	t_args = (struct thread_data *) args;

	t_args->exp->fire_for_duration(t_args->duration);
	pthread_exit(NULL);
}