#!/usr/bin/python
from bcc import BPF
from bcc.utils import printb

# define BPF program
bpf_text= """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
        return 0;
    }
"""

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.trace_print()
