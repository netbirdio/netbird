#include <linux/if_ether.h> // ETH_P_IP
#include <linux/udp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
    struct iphdr  *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

   // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        bpf_printk("invalid size");
        return XDP_PASS;
    }

    // skip non IPv4 packages
    if (eth->h_proto != htons(ETH_P_IP)) {
       return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {
       return XDP_PASS;
    }

    // 2130706433 = 127.0.0.1
    if (ip->daddr != htonl(2130706433)) {
        return XDP_PASS;
    }

    if (udp->source != htons(51820)){
        return XDP_PASS;
    }

    bpf_printk("update udp ports, src: %d, dst: %d", htons(udp->source), htons(udp->dest));

    __be16 new_src_port = udp->dest;
    __be16 new_dst_port = htons(8081);
    udp->dest = new_dst_port;
    udp->source = new_src_port;
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";