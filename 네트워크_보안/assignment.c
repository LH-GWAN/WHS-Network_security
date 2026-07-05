#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void print_mac(u_char *mac) 
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02x%s", mac[i], (i < 5) ? ":" : "");
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) 
    {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if(ip -> iph_protocol != IPPROTO_TCP)
    {
        return;
    }
    int ip_header_len = ip->iph_ihl * 4;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;
    
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    printf("Src MAC : "); print_mac(eth->ether_shost);
    printf("Dst MAC : "); print_mac(eth->ether_dhost);
    printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));
    printf("Src Port : %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port : %d\n", ntohs(tcp->tcp_dport));
    printf("Https Message(크기: %d 바이트): \n", payload_len);
    for(int i = 0; i < payload_len; i++)
    {
        if(isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r')
        {
            printf("%c", payload[i]);
        }
        else
        {
            printf(".");
        }
    }
}

int main(void)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;
    
    handle = pcap_open_live("enp0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "실패: %s\n", errbuf);
        return 1;
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) 
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

}
