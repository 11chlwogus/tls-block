#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap.h>

// 1. 사용자 정의 네트워크 헤더 구조체 (libnet 미사용)
#pragma pack(push, 1)
struct MacHdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IpHdr {
    uint8_t v_ihl; // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;

    uint8_t ihl() const { return v_ihl & 0x0F; }
};

struct TcpHdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t off_res; // Data Offset (4 bits) + Reserved (4 bits)
    uint8_t flags;
    uint16_t win;
    uint16_t checksum;
    uint16_t urp;

    uint8_t th_off() const { return (off_res >> 4) & 0x0F; }
};

// TCP 체크섬 계산을 위한 가상 헤더
struct PseudoHdr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};
#pragma pack(pop)
