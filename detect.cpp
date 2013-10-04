/*
 * Author: Herat Gandhi (hag59)
 * Programs: This program detects TCP port scanning from other
 * hosts on a particular host.
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <map>
#include <utility>
#include <iostream>

using namespace std;

#define THRESHOLD 10

//Structure to keep track of TCP state per IP, per port
struct stat
{
	int state;
};

//Structure to keep track of TCP state per IP
struct storage
{
	int full_open;
	int half_open;
	int reset;
	int data_transfer;
	int syn_counts;
	map<int,stat> port;
};
//Main data structure in which all the events are logged.
map<string, storage> logger;

void process_packet(u_char *, const struct pcap_pkthdr *,
		const u_char *);
void process_tcp_packet(const u_char *  , int );

struct sockaddr_in source,dest;
int tcp=0,others=0,total=0,i,j;
string key;
int key1;
stat temp;
int syn,rst,ack,fin;
string myip = "192.168.48.146";
int print_alert = 0;
 
int main(int argc,char*argv[])
{
	//Handle of the pcap device/file
    pcap_t *handle;
    //Mode of operation: file/device
    int mode;
    char errbuf[100] , *devname;
    char *fname;
    int packets;
    int data,full,half,syn,reset,result;

    //If number of command line arguments are less than
    // 5 then show user how to use this program.
    if(argc < 5)
    {
    	cout<<"Usage: ./Program Mode Options Your_IP Number_of_packets\n";
    	cout<<"        Mode: 1 - File, 2 - Device\n";
    	cout<<"        Options: 1 - File name\n";
    	cout<<"        Options: 2 - Interface name"
    			"(E.g., eth0)\n";
    	exit(1);
    }
    //Retrieve the mode from cmd-arg
    mode = atoi(argv[1]);

    if(mode == 1)
    {
    	//Mode is file input
    	myip = argv[3]; //Get user's IP
    	fname = argv[2]; //Get pcap file name
    	//Open the pcap file and get the handle
    	handle = pcap_open_offline(fname,errbuf);
    	//Get the number of packets to be processed
    	packets = atoi(argv[4]);
    	//Process the whole file until no packet
    	// is left.
    	pcap_loop(handle ,packets, process_packet , NULL);
    }
    else if(mode == 2)
    {
    	//Mode is device
    	myip = argv[3]; //Get user's IP
    	devname = argv[2]; //Get device interface name
    	handle = pcap_open_live(devname,65536,1,0,errbuf);
    	//If could not open the device then print error
    	// and exit
    	if (handle == NULL)
		{
			fprintf(stderr,"Couldn't open device %s : %s\n",
					devname , errbuf);
			exit(1);
		}
    	//Get the number of packets to be processed
		packets = atoi(argv[4]);
    	//Process 1000 packets from the interface
    	pcap_loop(handle, packets, process_packet, NULL);
    }
    //Print the potential threat ip list
    cout << "Potential threat:" << endl;
	for(map<string,storage>::iterator ite=logger.begin();
			ite!=logger.end(); ++ite)
	{
		key = (*ite).first; //Get the IP
		data = (*ite).second.data_transfer;
		full = (*ite).second.full_open;
		syn = (*ite).second.syn_counts;
		half = (*ite).second.half_open;
		reset = (*ite).second.reset;

		//Compute the potential threat score using the stored
		// statistics
		result = (full-data)+half+reset;
		//If the final score is > threshold then print the
		// IP as threat
		if(result > THRESHOLD)
		{
			cout << "IP: " << key << endl;
			cout << "   Number of Half-open connections: "<<half<<endl;
			cout << "   Number of complete connections: "<<full<<endl;
			cout << "   Number of reset connections: " <<reset<<endl;
		}
	}
    return 0;
}

/*
 * Print Statistics:
 * 		Print the potential threats here.
 * 		This is a running list.
 */
void print_statistics(string str)
{
	//Check if crossed threshold
	if(((logger[str].full_open - logger[str].data_transfer)
			+ logger[str].half_open + logger[str].reset)
			> THRESHOLD)
	{
		cout << "Alert! IP: " << str << endl;
	}
}

/*
 * Process Packet:
 *    Processes the packet header and if the packet is of TCP
 * then only it passes to other function for further processing
 * otherwise just ignores the packet.
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *buffer)
{
    int size = header->len;
    //Get the IP Header part of this packet, excluding the Ethernet
    // header
    struct iphdr *iph = (struct iphdr*)(buffer +
    		sizeof(struct ethhdr));
    ++total;
    //Check the Protocol and do accordingly
    switch (iph->protocol)
    {
        case 6: //TCP Protocol
            ++tcp;
            process_tcp_packet(buffer, size);
            break;
        default: //Some Other Protocols
            ++others;
            break;
    }
}

/*
 * Process TCP packet:
 *    Processes the TCP packets. Using various flags, IP addresses
 * and port addresses maintains the statistics about various hosts.
 */
void process_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
    int destp,srcp;
    unsigned long seq;
    int flag = 0;
    struct iphdr *iph = (struct iphdr *)(Buffer +
    		sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer +
    		iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) +
    		iphdrlen + tcph->doff*4;
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    //Get the source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	//Get the destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	//Get various flags
	syn = (unsigned int)tcph->syn;
	rst = (unsigned int)tcph->rst;
	fin = (unsigned int)tcph->fin;
	ack = (unsigned int)tcph->ack;

	//Get the port numbers and sequence number
	destp = ntohs(tcph->dest);
	srcp = ntohs(tcph->source);
	seq = ntohl((unsigned long)tcph->seq);

	//Handle incoming SYN packets
	if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0
			&& syn == 1 && ack == 0)
    {
		//Source IP is the primary key
		key = inet_ntoa(source.sin_addr);
		//Destination port is the secondary key
		key1 = destp;
		//State = 1 indicating SYN is received
		temp.state = 1;
		logger[key].port[key1] = temp;
		//Increment SYN count
		logger[key].syn_counts++;
    }
	//Handle outgoing SYN+ACK packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) == 0
    		&& syn == 1 && ack == 1)
    {
    	//Destination IP is the primary key
    	key = inet_ntoa(dest.sin_addr);
    	//Source port is the secondary key
    	key1 = srcp;
    	//If SYN was received earlier then only consider
    	if(logger[key].port[key1].state == 1)
    	{
    		//State = 2 indicating SYN+ACK in opposite direction
			temp.state = 2;
			logger[key].port[key1] = temp;
    	}
    }
	//Handle incoming ACK packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0
    		&& ack == 1 && seq >= 1)
	{
    	//Source IP is the primary key
    	key = inet_ntoa(source.sin_addr);
    	//Destination port is the secondary key
		key1 = destp;
		//If SYN+ACK was the last entry
		if(logger[key].port[key1].state == 2)
		{
			//State = 3 indicating complete handshake
			temp.state = 3;
			logger[key].port[key1] = temp;
			//Increment full open count
			logger[key].full_open++;
			flag = 1;
		}
	}
	//Handle incoming RST packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0
    		&& rst == 1)
	{
    	//Source IP is the primary key
    	key = inet_ntoa(source.sin_addr);
    	//Destination port is the secondary key
		key1 = destp;
		//If SYN+ACK was the last entry
		if(logger[key].port[key1].state == 2)
		{
			//State = 7 indicating half open connection
			temp.state = 7;
			logger[key].port[key1] = temp;
			//Increment half open count
			logger[key].half_open++;
			flag = 1;
		}
	}
	//Handle outgoing RST packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) == 0
    		&& rst == 1)
	{
    	//Destination IP is the primary key
    	key = inet_ntoa(dest.sin_addr);
    	//Source port is the secondary key
		key1 = srcp;
		//If previous state was SYN or FIN
		if(logger[key].port[key1].state == 1 ||
				logger[key].port[key1].state == 6)
		{
			//State = 5 indicating RST
			temp.state = 5;
			logger[key].port[key1] = temp;
			//Increment reset count
			logger[key].reset++;
			flag = 1;
		}
	}
	//Handle incoming data transfer
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0
    		&& ack == 1 && seq >= 1)
    {
    	//Source IP is the primary key
    	key = inet_ntoa(source.sin_addr);
    	//Destination port is the secondary key
		key1 = destp;
		//If previous state was full handshake
		if(logger[key].port[key1].state == 3)
		{
			//State = 4 indicating data transfer
			temp.state = 4;
			logger[key].port[key1] = temp;
			//Increment data transfer count
			logger[key].data_transfer++;
			flag = 1;
		}
    }
	//Handle outgoing data transfer
    else if(strcmp(inet_ntoa(dest.sin_addr),myip.c_str()) != 0
    		&& ack == 1 && seq >= 1)
	{
    	//Destination IP is the primary key
		key = inet_ntoa(dest.sin_addr);
		//Source port is the secondary key
		key1 = srcp;
		//If previous state was full handshake
		if(logger[key].port[key1].state == 3)
		{
			//State = 4 indicating data transfer
			temp.state = 4;
			logger[key].port[key1] = temp;
			//Increment data transfer count
			logger[key].data_transfer++;
			flag = 1;
		}
	}
	//Handle incoming FINs
	else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0
			&& fin == 1 && ack == 0)
	{
		//Source IP is the primary key
		key = inet_ntoa(source.sin_addr);
		//Destination port is the secondary key
		key1 = destp;
		//State = 6 indicating FIN received
		temp.state = 6;
		logger[key].port[key1] = temp;
	}
	//Print alert for debugging
	if(flag == 1 && print_alert%150 == 0)
	{
		print_statistics(key);
	}
	print_alert++;
}
