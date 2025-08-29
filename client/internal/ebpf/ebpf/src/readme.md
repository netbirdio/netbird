# DNS forwarder

The agent attach the XDP program to the lo device. We can not use fake address in eBPF because the
traffic does not appear in the eBPF program. The program capture the traffic on wg_ip:53 and 
overwrite in it the destination port to 5053.

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
