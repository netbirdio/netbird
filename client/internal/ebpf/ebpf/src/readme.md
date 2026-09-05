# XDP programs

`prog.c` is attached to the `lo` device and dispatches to the features enabled in the
`nb_features` map. The only feature is the WireGuard proxy (`wg_proxy.c`): it rewrites
loopback UDP sent from the WireGuard listen port so it reaches the userspace relay proxy
port instead, and swaps the peer endpoint port into the source so the proxy can tell
peers apart.

Maps use the legacy `struct bpf_map_def` form, defined in `bpf_map_def.h` because libbpf
1.0 removed it. They load on kernels built without BTF, which BTF-style (`SEC(".maps")`)
definitions do not.

Regenerate the objects with `go generate ./client/internal/ebpf/ebpf/`; it needs
`clang-14`. Loading a regenerated object needs root, attaching it needs `bpf_link`
(kernel >= 5.7), and only one XDP program can own `lo` at a time.

# Debug

The CONFIG_BPF_EVENTS kernel module is required for bpf_printk.
Apply this code to use bpf_printk
```
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
```
