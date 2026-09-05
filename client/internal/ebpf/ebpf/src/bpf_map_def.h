// libbpf 1.3 removed struct bpf_map_def, but the programs here keep the legacy
// map definitions: they load on kernels built without BTF, which BTF-style
// (SEC(".maps")) definitions do not. Define the struct ourselves so the
// programs compile against current libbpf headers.
#ifndef NB_BPF_MAP_DEF_H
#define NB_BPF_MAP_DEF_H

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

#endif
