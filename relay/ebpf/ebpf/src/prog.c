#include <stdbool.h>
#include <linux/if_ether.h> // ETH_P_IP
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define RELAY_PORT 8083
#define RELAY_PORT_BE ((__be16) __constant_htons(RELAY_PORT))

struct peer_value {
    __be32 dest_ip;                     // 4 bytes
    __be16 dest_port;                   // 2 bytes
    __u16  dst_id;                      // 2 bytes (aligned)
    __u8   dst_mac[ETH_ALEN];           // 6 bytes
    __u8   src_mac[ETH_ALEN];           // 6 bytes
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);          // 2-byte ID key
    __type(value, struct peer_value);
} peers_map SEC(".maps");

static __always_inline int xdp_wg_proxy(struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, void *data_end, struct xdp_md *ctx) {
    void *payload = (void *)udp + sizeof(struct udphdr);
    if (payload + 4 > data_end)
        return XDP_PASS;

    __u8 *p = payload;

    // Validate version and message type
    if (p[0] != 1 || p[1] != 12) {
        return XDP_PASS;
    }

    // Extract channel_id (big endian)
    __u16 channel_id = ((__u16)p[2] << 8) | (__u16)p[3];

    struct peer_value *peer = bpf_map_lookup_elem(&peers_map, &channel_id);
    if (!peer) {
        return XDP_PASS;
    }

    // Overwrite channel_id with dst_id
    p[2] = (__u8)(peer->dst_id >> 8);
    p[3] = (__u8)(peer->dst_id & 0xff);

    // Store original destination (relay server) IP and port for source rewriting
    __be32 relay_ip = ip->daddr;
    __be16 relay_port = udp->dest;

    // Change destination IP and port to peer
    ip->daddr = peer->dest_ip;
    udp->dest = peer->dest_port;

    // Change source IP and port to relay server (masquerade as relay)
    ip->saddr = relay_ip;
    udp->source = relay_port;

    // Decrement TTL for routing
    if (ip->ttl <= 1) {
        return XDP_PASS;  // Let kernel handle TTL exceeded
    }
    ip->ttl--;

    // Recalculate IP checksum
    ip->check = 0;
    __u32 csum = 0;
    __u16 *ip_header = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        csum += (__u32)ip_header[i];
    }
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    ip->check = ~csum;

    // Recalculate UDP checksum manually
    udp->check = 0;

    // Recalculate payload pointer with fresh bounds check
    void *udp_payload = (void *)udp + sizeof(struct udphdr);

    // Calculate UDP length
    __u16 udp_len = bpf_ntohs(udp->len);
    __u16 payload_len = udp_len - sizeof(struct udphdr);

    // Bounds check for payload length
    if (payload_len > 1472) {  // Max UDP payload in standard MTU
        return XDP_DROP;
    }

    // Bounds check for full UDP datagram
    if (udp_payload + payload_len > data_end) {
        return XDP_DROP;
    }

    // Pseudo-header checksum
    __u32 udp_csum = 0;
    udp_csum += (ip->saddr >> 16) & 0xffff;
    udp_csum += ip->saddr & 0xffff;
    udp_csum += (ip->daddr >> 16) & 0xffff;
    udp_csum += ip->daddr & 0xffff;
    udp_csum += bpf_htons(IPPROTO_UDP);
    udp_csum += udp->len;

    // Add UDP header (4 16-bit words)
    __u16 *udp_ptr = (__u16 *)udp;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        udp_csum += udp_ptr[i];
    }

    // Add payload
    __u16 *payload_ptr = (__u16 *)udp_payload;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 736; i++) {  // 736 * 2 = 1472 max payload
        if (i * 2 + 2 > payload_len)
            break;
        if ((void *)(payload_ptr + i) + 2 > data_end)
            break;
        udp_csum += payload_ptr[i];
    }

    // Handle odd byte
    if (payload_len & 1) {
        __u8 *last_byte = (__u8 *)udp_payload + payload_len - 1;
        if ((void *)last_byte + 1 <= data_end) {
            udp_csum += (*last_byte) << 8;
        }
    }

    // Fold carries
    udp_csum = (udp_csum & 0xffff) + (udp_csum >> 16);
    udp_csum = (udp_csum & 0xffff) + (udp_csum >> 16);

    udp->check = ~(__u16)udp_csum;
    if (udp->check == 0)
        udp->check = 0xffff;

    __builtin_memcpy(eth->h_dest, peer->dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, peer->src_mac, ETH_ALEN);

    return XDP_TX;
}

SEC("xdp/relay_xdp_prog")
int relay_xdp_prog(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr  *ip  = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    if (udp->dest != RELAY_PORT_BE) {
        return XDP_PASS;
    }

    return xdp_wg_proxy(eth, ip, udp, data_end, ctx);
}

char _license[] SEC("license") = "GPL";
