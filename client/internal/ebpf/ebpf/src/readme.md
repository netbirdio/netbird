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
