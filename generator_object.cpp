#include <tins/tins.h>
#include <sys/time.h>
#include <vector>
#include <unistd.h>
#include "generator_helpers.h"

using namespace Tins;
using namespace std;

#define MAX_FLOWS 1000

class Press {
	public:
		void showMe(CBRHelper &exp){
			RawPDU *payload = exp.findRawPDU();
			cout << "--->Payload: " << payload->payload_size() << endl;
			
			IP *ip = exp.findIP();
			cout << "--->IP, src: " << ip->src_addr() << ", dst: " <<
				ip->dst_addr() << endl;
			
			cout << "--->Iface name: " << exp.getIfOutName() <<
				", src MAC: " << exp.getIfHwAddr() << endl;
		}

};

int main() {
	//Initialization
	//CBRHelper exp;

	MultipleCBRHelper exp;
	
	//check the class method for the order of introduction of parameters
	//exp.set_basic_cbr_stream();
	//double rate = 10e6;
	//exp.set_high_speed_cbr_stream(rate);

	//uint16_t dst_udp = 9000;
	//uint16_t src_udp = dst_udp;

	int num_flows = 5;

	//global parameters for this experiment
	struct global_settings settings;
	settings.eth.dst_addr("00:40:f4:56:cc:01");
	settings.i_o = "eth0";
	settings.dst_ip = "193.168.168.1";
	settings.src_ip = "193.168.168.102";
	settings.rate = 10e6;
	settings.dst_udp = 9000;
	settings.src_udp = settings.dst_udp;

	if (num_flows < MAX_FLOWS)
	{
		for (int f = 0; f < num_flows; f++)
		{
			exp.addFlow(settings);
			settings.src_udp++;
			settings.dst_udp++;
		}
	}
	
	//Showing on terminal the information of the experiment
	//Press p;
	//p.showMe(exp);

	//Generating the sender and firing through the interface
	double duration = 5.0; //seconds
	//exp.fire();
	//exp.fire_for_duration(duration);
	exp.multiple_fire_for_duration(duration);

	return 0;
}
