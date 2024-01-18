const __u32 map_key_proxy_port = 0;
const __u32 map_key_wg_port = 1;

struct bpf_map_def SEC("maps") nb_wg_proxy_settings_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u16),
	.max_entries = 10,
};

__u16 proxy_port = 0;
__u16 wg_port = 0;

bool read_port_settings() {
    __u16 *value;
    value = bpf_map_lookup_elem(&nb_wg_proxy_settings_map, &map_key_proxy_port);
    if (!value) {
        return false;
    }

    proxy_port = *value;

    value = bpf_map_lookup_elem(&nb_wg_proxy_settings_map, &map_key_wg_port);
    if (!value) {
        return false;
    }
    wg_port = htons(*value);

    return true;
}

int xdp_wg_proxy(struct iphdr  *ip, struct udphdr *udp) {
    if (proxy_port == 0 || wg_port == 0) {
        if (!read_port_settings()){
            return XDP_PASS;
        }
        // bpf_printk("proxy port: %d, wg port: %d", proxy_port, wg_port);
    }

    // 2130706433 = 127.0.0.1
    if (ip->daddr != htonl(2130706433)) {
        return XDP_PASS;
    }

    if (udp->source != wg_port){
        return XDP_PASS;
    }

    __be16 new_src_port = udp->dest;
    __be16 new_dst_port = htons(proxy_port);
    udp->dest = new_dst_port;
    udp->source = new_src_port;
	return XDP_PASS;
}
