#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    printf("Packet capture length: %d\n", pkt_header->caplen);
    printf("Packet total length: %d\n", pkt_header->len);
    // Here you can parse the TCP/IP headers to extract the payload

    // packet_t packet = rawsocket_sniff();

}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter;
    char filter_exp[] = "tcp port 8080 and host 127.0.0.1";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char *dev = "lo0"; // Explicitly set to loopback interface on macOS, or "lo" on Linux

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &filter) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_freecode(&filter);
    pcap_close(handle);

    return (0);
}