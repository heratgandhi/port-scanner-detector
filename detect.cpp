#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>         //for exit()
#include <string.h>         //for memset
 
#include <sys/socket.h>
#include <arpa/inet.h>      //for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>     //Provides declarations for ip header

#include <map>
#include <utility>
#include <iostream>

using namespace std;

#define MY_IP "192.168.48.146"

struct stat
{
	int syn;
	int rst;
	int ack;
	int fin;
};

struct substorage
{
	map<int,stat> my_port;
};

struct storage
{
	map<int,substorage> opp_port;
};
 
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void PrintData (const u_char * , int);
 
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,others=0,total=0,i,j;
map<string, storage> logger;
string key;
stat temp;
int opp,mine;
int syn,rst,ack,fin;
 
int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed
 
    char errbuf[100] , *devname;
    int count = 1 , n;
     
    devname = "eth0";
     
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    //handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    handle = pcap_open_offline("test1.pcap",errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create file.");
    }
     
    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);

	for( map<string, storage>::iterator ii=logger.begin(); ii!=logger.end(); ++ii)
	{
		key = (*ii).first;
		cout << key << endl;
		for( map<int, substorage>::iterator jj=logger[key].opp_port.begin(); jj!=logger[key].opp_port.end(); ++jj)
		{
			opp = (*jj).first;
			cout << "  " << opp << endl;
			for( map<int, stat>::iterator kk=logger[key].opp_port[opp].my_port.begin(); kk!=logger[key].opp_port[opp].my_port.end(); ++kk)
			{
				mine = (*kk).first;
				cout << "   " << logger[key].opp_port[opp].my_port[mine].ack << " " <<
						logger[key].opp_port[opp].my_port[mine].fin << " " <<
						logger[key].opp_port[opp].my_port[mine].rst << " " <<
						logger[key].opp_port[opp].my_port[mine].syn << endl;
			}
		}
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
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

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

    if(strcmp(inet_ntoa(source.sin_addr),MY_IP) == 0)
    {
    	key = inet_ntoa(dest.sin_addr);
    	opp = ntohs(tcph->dest);
    	mine = ntohs(tcph->source);
    }
    else
    {
    	key = inet_ntoa(source.sin_addr);
    	opp = ntohs(tcph->source);
		mine = ntohs(tcph->dest);
    }

    syn = (unsigned int)tcph->syn;
    rst = (unsigned int)tcph->rst;
    fin = (unsigned int)tcph->fin;
    ack = (unsigned int)tcph->ack;

    if(logger.find(key) == logger.end())
    {
    	//not found key
    	temp.ack = ack;
    	temp.rst = rst;
    	temp.fin = fin;
    	temp.syn = syn;
    	logger[key].opp_port[opp].my_port[mine] = temp;
    }
    else
    {
    	//found key
    	if(logger[key].opp_port.find(opp) == logger[key].opp_port.end())
    	{
    		//not found opp
    		temp.ack = ack;
			temp.rst = rst;
			temp.fin = fin;
			temp.syn = syn;
    		logger[key].opp_port[opp].my_port[mine] = temp;
    	}
    	else
    	{
    		//found opp
    		if(logger[key].opp_port[opp].my_port.find(mine) == logger[key].opp_port[opp].my_port.end())
    		{
    			//not found mine
    			temp.ack = ack;
				temp.rst = rst;
    			temp.fin = fin;
				temp.syn = syn;
				logger[key].opp_port[opp].my_port[mine] = temp;
    		}
    		else
    		{
    			//found mine
				logger[key].opp_port[opp].my_port[mine].ack += ack;
				logger[key].opp_port[opp].my_port[mine].rst += rst;
				logger[key].opp_port[opp].my_port[mine].fin += fin;
				logger[key].opp_port[opp].my_port[mine].syn += syn;
    		}
    	}
    }
}
