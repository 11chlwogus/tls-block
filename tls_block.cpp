#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap.h>

#include "protocol_hdr.h"

uint16_t calculate_checksum(const uint16_t *data, size_t bytes) {
    uint32_t sum = 0;
    const uint8_t *ptr = (const uint8_t *)data;

    while (bytes > 1) {
        sum += (ptr[0] << 8) + ptr[1];
        ptr += 2;
        bytes -= 2;
    }
    if (bytes == 1) {
        sum += (ptr[0] << 8); 
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons((uint16_t)(~sum));
}

uint16_t calculate_tcp_checksum(IpHdr* ip, TcpHdr* tcp, const uint8_t* payload, size_t payload_len) {
    PseudoHdr pseudo;
    pseudo.src_ip = ip->src;
    pseudo.dst_ip = ip->dst;
    pseudo.reserved = 0;
    pseudo.protocol = ip->protocol;
    
    size_t tcp_hdr_len = tcp->th_off() * 4;
    size_t tcp_total_len = tcp_hdr_len + payload_len;
    pseudo.tcp_len = htons((uint16_t)tcp_total_len);

    uint8_t buf[65535];
    std::memset(buf, 0, sizeof(buf));

    std::memcpy(buf, &pseudo, sizeof(PseudoHdr));
    std::memcpy(buf + sizeof(PseudoHdr), tcp, tcp_hdr_len);
    if (payload_len > 0 && payload != nullptr) {
        std::memcpy(buf + sizeof(PseudoHdr) + tcp_hdr_len, payload, payload_len);
    }

    size_t total_bytes = sizeof(PseudoHdr) + tcp_total_len;
    return calculate_checksum(reinterpret_cast<const uint16_t*>(buf), total_bytes);
}

bool parse_tls_sni(const uint8_t* tls_data, int tls_len, std::string& sni_name) {
    if (tls_len < 5) return false;
    uint8_t content_type = tls_data[0];
    if (content_type != 0x16) return false;

    int handshake_offset = 5;
    if (tls_len < handshake_offset + 4) return false;
    uint8_t handshake_type = tls_data[handshake_offset];
    if (handshake_type != 0x01) return false;

    int offset = handshake_offset + 4 + 2 + 32; 
    if (offset >= tls_len) return false;

    uint8_t session_id_len = tls_data[offset];
    offset += 1 + session_id_len; 

    if (offset + 2 > tls_len) return false;
    uint16_t cipher_suites_len = (tls_data[offset] << 8) | tls_data[offset+1];
    offset += 2 + cipher_suites_len;

    if (offset + 1 > tls_len) return false;
    uint8_t comp_methods_len = tls_data[offset];
    offset += 1 + comp_methods_len;

    if (offset + 2 > tls_len) return false;
    uint16_t extensions_len = (tls_data[offset] << 8) | tls_data[offset+1];
    offset += 2;

    int extensions_end = offset + extensions_len;
    if (extensions_end > tls_len) extensions_end = tls_len;

    while (offset + 4 <= extensions_end) {
        uint16_t ext_type = (tls_data[offset] << 8) | tls_data[offset+1];
        uint16_t ext_len = (tls_data[offset+2] << 8) | tls_data[offset+3];
        offset += 4;

        if (ext_type == 0x0000) { 
            if (offset + 5 <= extensions_end) {
                uint16_t sni_len = (tls_data[offset+3] << 8) | tls_data[offset+4];
                if (offset + 5 + sni_len <= extensions_end) {
                    sni_name = std::string((const char*)&tls_data[offset+5], sni_len);
                    return true;
                }
            }
        }
        offset += ext_len;
    }
    return false;
}

void send_forward_rst(pcap_t* handle, const uint8_t* orig_packet) {
    std::vector<uint8_t> block_packet(sizeof(MacHdr) + sizeof(IpHdr) + sizeof(TcpHdr), 0);
    
    MacHdr* orig_mac = (MacHdr*)orig_packet;
    IpHdr* orig_ip = (IpHdr*)(orig_packet + sizeof(MacHdr));
    TcpHdr* orig_tcp = (TcpHdr*)(orig_packet + sizeof(MacHdr) + (orig_ip->ihl() * 4));

    MacHdr* next_mac = (MacHdr*)block_packet.data();
    IpHdr* next_ip = (IpHdr*)(block_packet.data() + sizeof(MacHdr));
    TcpHdr* next_tcp = (TcpHdr*)(block_packet.data() + sizeof(MacHdr) + sizeof(IpHdr));

    std::memcpy(next_mac->dst, orig_mac->dst, 6);
    std::memcpy(next_mac->src, orig_mac->src, 6);
    next_mac->type = orig_mac->type;

    next_ip->v_ihl = 0x45; 
    next_ip->tos = orig_ip->tos;
    next_ip->len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    next_ip->id = htons(12345); 
    next_ip->flags_frag = 0;
    next_ip->ttl = orig_ip->ttl;
    next_ip->protocol = IPPROTO_TCP;
    next_ip->src = orig_ip->src;
    next_ip->dst = orig_ip->dst;
    next_ip->checksum = 0;
    next_ip->checksum = calculate_checksum((uint16_t*)next_ip, sizeof(IpHdr));

    next_tcp->sport = orig_tcp->sport;
    next_tcp->dport = orig_tcp->dport;
    
    size_t orig_payload_len = ntohs(orig_ip->len) - (orig_ip->ihl() * 4) - (orig_tcp->th_off() * 4);
    next_tcp->seq = htonl(ntohl(orig_tcp->seq) + orig_payload_len);
    next_tcp->ack = orig_tcp->ack;
    
    next_tcp->off_res = (sizeof(TcpHdr) / 4) << 4;
    next_tcp->flags = 0x04; 
    next_tcp->win = orig_tcp->win;
    next_tcp->checksum = 0;
    next_tcp->checksum = calculate_tcp_checksum(next_ip, next_tcp, nullptr, 0);

    pcap_sendpacket(handle, block_packet.data(), block_packet.size());
}

void send_backward_rst(int raw_socket, const uint8_t* orig_packet) {
    size_t total_packet_size = sizeof(IpHdr) + sizeof(TcpHdr);
    std::vector<uint8_t> block_packet(total_packet_size, 0);

    IpHdr* orig_ip = (IpHdr*)(orig_packet + sizeof(MacHdr));
    TcpHdr* orig_tcp = (TcpHdr*)(orig_packet + sizeof(MacHdr) + (orig_ip->ihl() * 4));

    IpHdr* next_ip = (IpHdr*)block_packet.data();
    TcpHdr* next_tcp = (TcpHdr*)(block_packet.data() + sizeof(IpHdr));

    next_ip->v_ihl = 0x45;
    next_ip->tos = orig_ip->tos;
    next_ip->len = htons(total_packet_size);
    next_ip->id = htons(54321); 
    next_ip->flags_frag = 0;
    next_ip->ttl = 128; 
    next_ip->protocol = IPPROTO_TCP;
    next_ip->src = orig_ip->dst; 
    next_ip->dst = orig_ip->src;
    next_ip->checksum = 0;
    next_ip->checksum = calculate_checksum((uint16_t*)next_ip, sizeof(IpHdr));

    next_tcp->sport = orig_tcp->dport; 
    next_tcp->dport = orig_tcp->sport;
    
    next_tcp->seq = orig_tcp->ack;     
    next_tcp->ack = 0; 
    
    next_tcp->off_res = (sizeof(TcpHdr) / 4) << 4;
    next_tcp->flags = 0x04; 
    
    next_tcp->win = orig_tcp->win;
    next_tcp->checksum = 0;
    next_tcp->checksum = calculate_tcp_checksum(next_ip, next_tcp, nullptr, 0);

    struct sockaddr_in sin;
    std::memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = next_tcp->dport;
    sin.sin_addr.s_addr = next_ip->dst;

    sendto(raw_socket, block_packet.data(), block_packet.size(), 0, (struct sockaddr*)&sin, sizeof(sin));
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "syntax : tls-block <interface> <server name>" << std::endl;
        return -1;
    }

    char* dev = argv[1];
    std::string target_server = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) return -1;

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0) return -1;
    int on = 1;
    setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    std::cout << "[*] Sniffing started on " << dev << "... Target Server: [" << target_server << "]" << std::endl;

    struct pcap_pkthdr* header;
    const uint8_t* packet;

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        if (header->caplen < sizeof(MacHdr) + sizeof(IpHdr)) continue;

        MacHdr* mac = (MacHdr*)packet;
        if (ntohs(mac->type) != 0x0800) continue; 

        IpHdr* ip = (IpHdr*)(packet + sizeof(MacHdr));
        if (ip->protocol != IPPROTO_TCP) continue; 

        size_t ip_hdr_len = ip->ihl() * 4;
        if (header->caplen < sizeof(MacHdr) + ip_hdr_len + sizeof(TcpHdr)) continue;

        TcpHdr* tcp = (TcpHdr*)(packet + sizeof(MacHdr) + ip_hdr_len);
        size_t tcp_hdr_len = tcp->th_off() * 4;
        
        size_t total_headers_len = sizeof(MacHdr) + ip_hdr_len + tcp_hdr_len;
        if (header->caplen < total_headers_len) continue;

        int payload_len = ntohs(ip->len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len <= 0) continue;

        const uint8_t* payload = packet + total_headers_len;

        std::string extracted_sni = "";
        if (parse_tls_sni(payload, payload_len, extracted_sni)) {
            if (extracted_sni.find(target_server) != std::string::npos) {
                std::cout << "[!] Target SNI matched! (" << extracted_sni << ") Injecting block packets..." << std::endl;
                send_forward_rst(handle, packet);
                send_backward_rst(raw_socket, packet);
            }
        }
    }

    close(raw_socket);
    pcap_close(handle);
    return 0;
}
