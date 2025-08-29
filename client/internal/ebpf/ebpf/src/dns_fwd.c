const __u32 map_key_dns_ip = 0;
const __u32 map_key_dns_port = 1;

struct bpf_map_def SEC("maps") nb_map_dns_ip = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 10,
};

struct bpf_map_def SEC("maps") nb_map_dns_port = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u16),
	.max_entries = 10,
};

__be32 dns_ip = 0;
__be16 dns_port = 0;

// 13568 is 53 in big endian
__be16 GENERAL_DNS_PORT = 13568;

bool read_settings() {
    __u16 *port_value;
    __u32 *ip_value;

    // read dns ip
    ip_value = bpf_map_lookup_elem(&nb_map_dns_ip, &map_key_dns_ip);
    if(!ip_value) {
        return false;
    }
    dns_ip = htonl(*ip_value);

    // read dns port
    port_value = bpf_map_lookup_elem(&nb_map_dns_port, &map_key_dns_port);
    if (!port_value) {
        return false;
    }
    dns_port = htons(*port_value);
    return true;
}

int xdp_dns_fwd(struct iphdr  *ip, struct udphdr *udp) {
    if (dns_port == 0) {
        if(!read_settings()){
            return XDP_PASS;
        }
        // bpf_printk("dns port: %d", ntohs(dns_port));
        // bpf_printk("dns ip: %d", ntohl(dns_ip));
    }

    if (udp->dest == GENERAL_DNS_PORT && ip->daddr == dns_ip) {
        udp->dest = dns_port;
        return XDP_PASS;
    }

    if (udp->source == dns_port && ip->saddr == dns_ip) {
        udp->source = GENERAL_DNS_PORT;
        return XDP_PASS;
    }

    return XDP_PASS;
}
