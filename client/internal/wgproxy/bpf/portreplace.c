#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_PKTGEN_UDP_PORT 9

#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })


// L3/L4 offsets
#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source ))
#define L4_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest ))
#define L4_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))


SEC("sched_act/socket1")
int myapp(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth  = data;
    struct iphdr  *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

   // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        bpf_printk("invalid size");
        return -1;
    }

    // skip non IP packages
    if (eth->h_proto != htons(ETH_P_IP)) {
       return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_UDP) {
       bpf_printk("skip non udp pkg");
       return TC_ACT_OK;
    }

    // 16777343 = 127.0.0.1
    if (ip->daddr != 16777343) {
        bpf_printk("invalid daddr: %d", ip->daddr);
        return TC_ACT_OK;
    }

    if (htons(udp->source) != 51820){
        bpf_printk("invalid sport: %d", htons(udp->source));
        return TC_ACT_OK;
    }

    bpf_printk("udp ports: %d, %d", htons(udp->source), htons(udp->dest));

    // todo store it on 32 and write it in one step
    __be16 new_src_port = udp->dest;
    __be16 new_dst_port = htons(8081);
    bpf_skb_store_bytes(skb, L4_SPORT_OFF, &new_src_port, 2, BPF_F_RECOMPUTE_CSUM);
    bpf_skb_store_bytes(skb, L4_DPORT_OFF, &new_dst_port, 2, BPF_F_RECOMPUTE_CSUM);

	return BPF_OK;
}
char _license[] SEC("license") = "GPL";

/*
    unsigned char bytes[4];
    bytes[0] = dst_ip & 0xFF;
    bytes[1] = (dst_ip >> 8) & 0xFF;
    bytes[2] = (dst_ip >> 16) & 0xFF;
    bytes[3] = (dst_ip >> 24) & 0xFF;
*/