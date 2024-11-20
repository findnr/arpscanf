#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define BUFFER_SIZE 42
#define MAX_EVENTS 1024
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define BATCH_SIZE 256 // 每批次扫描的 IP 数量

struct arp_header {
    unsigned short hw_type;
    unsigned short proto_type;
    unsigned char hw_len;
    unsigned char proto_len;
    unsigned short opcode;
    unsigned char src_mac[6];
    unsigned char src_ip[4];
    unsigned char dst_mac[6];
    unsigned char dst_ip[4];
};

// IP地址字符串转换为32位整数
unsigned int ip_to_int(const char *ip) {
    unsigned int addr = 0;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr);
}

// 32位整数转换为IP地址字符串
void int_to_ip(unsigned int ip, char *ip_str) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
}

// 设置非阻塞模式
int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// 构造ARP请求数据包
void construct_arp_request(unsigned char *buffer, const char *src_ip, const char *dst_ip, const unsigned char *src_mac) {
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    struct arp_header *arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));

    // 构造以太网头部
    memset(eth_hdr->ether_dhost, 0xFF, 6); // 广播地址
    memcpy(eth_hdr->ether_shost, src_mac, 6); // 源MAC地址
    eth_hdr->ether_type = htons(ETH_P_ARP);

    // 构造ARP头部
    arp_hdr->hw_type = htons(1);
    arp_hdr->proto_type = htons(ETH_P_IP);
    arp_hdr->hw_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(ARP_REQUEST);
    memcpy(arp_hdr->src_mac, src_mac, 6);
    inet_pton(AF_INET, src_ip, arp_hdr->src_ip);
    memset(arp_hdr->dst_mac, 0, 6);
    inet_pton(AF_INET, dst_ip, arp_hdr->dst_ip);
}

// 打印MAC地址
void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 高分辨率延时
void delay_ms(int ms) {
    struct timespec req = {0};
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

// 扫描函数
void scan_batch(const char *iface, const char *src_ip, unsigned int start_ip, unsigned int end_ip) {
    int sock;
    struct ifreq ifr;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char src_mac[6];
    struct sockaddr_ll sa;

    // 创建原始套接字
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置非阻塞模式
    if (set_nonblocking(sock) < 0) {
        perror("Failed to set socket to non-blocking");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 获取接口信息
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get interface MAC address");
        close(sock);
        exit(EXIT_FAILURE);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(sock);
        exit(EXIT_FAILURE);
    }

    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_hatype = htons(1);
    sa.sll_pkttype = PACKET_BROADCAST;
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xFF, 6);

    // 初始化 epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("Failed to create epoll instance");
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; // 边缘触发模式
    ev.data.fd = sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("Failed to add socket to epoll");
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct epoll_event events[MAX_EVENTS];

    // 批量发送ARP请求
    for (unsigned int ip = start_ip; ip <= end_ip; ip++) {
        char target_ip[INET_ADDRSTRLEN];
        int_to_ip(ip, target_ip);

        memset(buffer, 0, BUFFER_SIZE);
        construct_arp_request(buffer, src_ip, target_ip, src_mac);

        if (sendto(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("Failed to send ARP request");
        }

        // 限制发送频率，避免过载
        if ((ip - start_ip) % BATCH_SIZE == 0) {
            delay_ms(10); // 每批次等待10ms
        }
    }

    // 接收ARP响应
    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100); // 100ms超时
        if (n < 0) {
            perror("epoll_wait failed");
            break;
        } else if (n == 0) {
            break; // 无事件发生，结束循环
        }

        for (int i = 0; i < n; i++) {
            if (events[i].events & EPOLLIN) {
                ssize_t len = recvfrom(events[i].data.fd, buffer, sizeof(buffer), 0, NULL, NULL);
                if (len > 0) {
                    struct arp_header *arp_resp = (struct arp_header *)(buffer + sizeof(struct ether_header));
                    if (ntohs(arp_resp->opcode) == ARP_REPLY) {
                        char resp_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, arp_resp->src_ip, resp_ip, INET_ADDRSTRLEN);
                        printf("IP: %s, MAC: ", resp_ip);
                        print_mac(arp_resp->src_mac);
                        printf("\n");
                    }
                }
            }
        }
    }

    close(sock);
}

// 主函数
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <source_ip> <subnet_mask>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    const char *src_ip = argv[2];
    int mask = atoi(argv[3]);

    if (mask < 1 || mask > 32) {
        fprintf(stderr, "Invalid subnet mask. Must be between 1 and 32.\n");
        return EXIT_FAILURE;
    }

    unsigned int net_addr = ip_to_int(src_ip) & ((0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF);
    unsigned int start_ip = net_addr + 1; // 跳过网络地址
    unsigned int end_ip = net_addr | (~((0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF));

    scan_batch(iface, src_ip, start_ip, end_ip);

    return EXIT_SUCCESS;
}
