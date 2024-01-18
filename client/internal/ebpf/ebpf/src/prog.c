#include <stdbool.h>
#include <linux/if_ether.h> // ETH_P_IP
#include <linux/udp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "dns_fwd.c"
#include "wg_proxy.c"

const __u16 flag_feature_wg_proxy = 0b01;
const __u16 flag_feature_dns_fwd = 0b10;

const __u32 map_key_features = 0;
struct bpf_map_def SEC("maps") nb_features = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u16),
	.max_entries = 10,
};

SEC("xdp")
int nb_xdp_prog(struct xdp_md *ctx) {
    __u16 *features;
    features = bpf_map_lookup_elem(&nb_features, &map_key_features);
    if (!features) {
        return XDP_PASS;
    }

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip  = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // return early if not enough data
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end){
        return XDP_PASS;
    }

    // skip non IPv4 packages
    if (eth->h_proto != htons(ETH_P_IP)) {
       return XDP_PASS;
    }

    // skip non UPD packages
    if (ip->protocol != IPPROTO_UDP) {
       return XDP_PASS;
    }

    if (*features & flag_feature_dns_fwd) {
        xdp_dns_fwd(ip, udp);
    }

    if (*features & flag_feature_wg_proxy) {
        xdp_wg_proxy(ip, udp);
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
