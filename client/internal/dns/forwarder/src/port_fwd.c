#include <stdbool.h>
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

const __u32 map_key_dns_ip = 0;
const __u32 map_key_dns_port = 1;

struct bpf_map_def SEC("maps") xdp_port_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u16),
	.max_entries = 10,
};

__be32 dns_ip = 0;
__be16 dns_port = 0;

bool read_port_settings() {
    __u16 *value;
    __be32 *ip_value;
    value = bpf_map_lookup_elem(&xdp_port_map, &map_key_dns_port);
    if(!value) {
        return false;
    }

    dns_port = htons(*value);

    ip_value = bpf_map_lookup_elem(&xdp_port_map, &map_key_dns_ip);
    if(!ip_value) {
        return false;
    }
    dns_ip = htonl(*ip_value);
    return true;
}

SEC("xdp")
int xdp_dns_port_fwd(struct xdp_md *ctx) {
    if(dns_port == 0) {
        if(!read_port_settings()){
            return XDP_PASS;
        }
        bpf_printk("dns port: %d", dns_port);
        bpf_printk("dns ip: %d", dns_ip);
    }

	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
    struct iphdr  *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
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
    if (ip->daddr != dns_ip) {
        return XDP_PASS;
    }

    // skip non dns ports
    if (udp->source != htons(53)){
        return XDP_PASS;
    }

    udp->dest = dns_port;
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";