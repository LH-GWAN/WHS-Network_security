#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_payload(const u_char *payload, int len)
{
    if (len <= 0) {
        printf("   [No Payload]\n");
        return;
    }

    int print_len = (len > 512) ? 512 : len;

    printf("   HTTP Message (%d bytes, showing %d):\n   ", len, print_len);

    for (int i = 0; i < print_len; i++) {
        if (isprint(payload[i])) {
            printf("%c", payload[i]);
        } else if (payload[i] == '\n') {
            printf("\n   ");
        } else if (payload[i] == '\r') {
            continue;
        } else {
            printf(".");
        }
    }

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    int ip_header_len = ip->iph_ihl * 4;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    printf("=============== TCP Packet ===============\n");

    printf("[Ethernet Header]\n");
    printf("   Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    printf("   Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("[IP Header]\n");
    printf("   Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

    int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    const u_char *payload = packet + total_header_len;

    print_payload(payload, payload_len);

    printf("\n");
}

int main(void)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char dev[] = "eth0";          // 필요하면 "enp0s3"로 변경
    char filter_exp[] = "tcp";    // HTTP만 보고 싶으면 "tcp port 80"

    bpf_u_int32 net = 0;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "pcap_compile failed");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "pcap_setfilter failed");
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s...\n", dev);

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
