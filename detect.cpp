#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <map>
#include <utility>
#include <iostream>
#include <time.h>

using namespace std;

struct stat
{
	int state;
};

struct storage
{
	int full_open;
	int half_open;
	int reset;
	int data_transfer;
	map<int,stat> port;
};

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *  , int );

struct sockaddr_in source,dest;
int tcp=0,others=0,total=0,i,j;
string key;
int key1;
stat temp;
int syn,rst,ack,fin;

string myip = "192.168.48.146";

map<string, storage> logger;
 
int main(int argc,char*argv[])
{
    pcap_t *handle;
    int mode;
    char errbuf[100] , *devname;
    char *fname;
    if(argc < 4)
    {
    	cout<<"Usage: ./Program Mode Options Your_IP\n";
    	cout<<"        Mode: 1 - File, 2 - Device\n";
    	cout<<"        Options: 1 - File name\n";
    	cout<<"        Options: 2 - Interface name\n";
    	exit(1);
    }
    mode = atoi(argv[1]);
    if(mode == 1)
    {
    	myip = argv[3];
    	fname = argv[2];
    	handle = pcap_open_offline(fname,errbuf);
    	pcap_loop(handle ,-1, process_packet , NULL);
    }
    else if(mode == 2)
    {
    	myip = argv[3];
    	devname = argv[2];
    	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    	if (handle == NULL)
		{
			fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
			exit(1);
		}
    	pcap_loop(handle, 1000, process_packet, NULL);
    }

	for(map<string,storage>::iterator ii=logger.begin(); ii!=logger.end(); ++ii)
	{
		key = (*ii).first;
		cout<<key<<endl;
		cout<<(*ii).second.data_transfer<<" "<<(*ii).second.full_open<<" "<<
				(*ii).second.half_open<<" "<<(*ii).second.reset<<endl;
	}

    return 0;
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    int destp,srcp;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	syn = (unsigned int)tcph->syn;
	rst = (unsigned int)tcph->rst;
	fin = (unsigned int)tcph->fin;
	ack = (unsigned int)tcph->ack;

	destp = ntohs(tcph->dest);
	srcp = ntohs(tcph->source);

	//cout<<inet_ntoa(source.sin_addr) << " ";
	//cout<<inet_ntoa(dest.sin_addr)<<endl;
	//cout <<syn<<" "<<rst<<" "<<fin<<" "<<endl;
	//cout << destp << " "<< srcp << "\n";

	//Handle incoming SYN packets
	if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0 && syn == 1 && ack == 0)
    {
		key = inet_ntoa(source.sin_addr);
		key1 = destp;
		temp.state = 1;
		logger[key].port[key1] = temp;
    }
	//Handle outgoing SYN+ACK packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) == 0 && syn == 1 && ack == 1)
    {
    	key = inet_ntoa(dest.sin_addr);
    	key1 = srcp;
    	if(logger[key].port[key1].state == 1)
    	{
			temp.state = 2;
			logger[key].port[key1] = temp;
    	}
    }
	//Handle incoming ACK packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0 && ack == 1 && tcph->seq == 1)
	{
    	key = inet_ntoa(source.sin_addr);
		key1 = destp;
		if(logger[key].port[key1].state == 2)
		{
			temp.state = 3;
			logger[key].port[key1] = temp;
			logger[key].full_open++;
		}
	}
	//Handle incoming RST packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0 && rst == 1)
	{
    	//cout<<"incoming rst\n";
    	key = inet_ntoa(source.sin_addr);
		key1 = destp;
		if(logger[key].port[key1].state == 2)
		{
			temp.state = 4;
			logger[key].port[key1] = temp;
			logger[key].half_open++;
			//cout<<"Increment\n";
		}
	}
	//Handle outgoing RST packets
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) == 0 && rst == 1)
	{
    	//cout<<"outgoing rst\n";
    	key = inet_ntoa(dest.sin_addr);
		key1 = srcp;
		if(logger[key].port[key1].state == 1)
		{
			temp.state = 3;
			logger[key].port[key1] = temp;
			logger[key].reset++;
			//cout<<key<<" Increment \n";
			//cout<<key1<<" Increment \n";
		}
	}
	//Handle data transfer
    else if(strcmp(inet_ntoa(source.sin_addr),myip.c_str()) != 0  && ack == 1 && tcph->seq > 1)
    {
    	key = inet_ntoa(source.sin_addr);
		key1 = destp;
		if(logger[key].port[key1].state == 3)
		{
			temp.state = 4;
			logger[key].port[key1] = temp;
			logger[key].data_transfer++;
		}
    }
}
/*fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);

	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );

	fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");

    fprintf(logfile , "\n###########################################################");*/
