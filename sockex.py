#!/usr/bin/env python
# -*- cofing: utf-8 -*-

from __future__ import print_function

import ctypes as ct
import os
import subprocess
import time

from bcc import BPF

prog = r"""
    // SPDX-License-Identifier: GPL-2.0+
    #define BPF_LICENSE GPL

     #include <uapi/linux/if_ether.h>
     #include <uapi/linux/if_packet.h>
     #include <uapi/linux/ip.h>
     #include <net/sock.h>
     #include <bcc/proto.h>

      // ★（1）BPFマップの定義
      BPF_ARRAY(my_map, long, 256);

       int bpf_prog(struct __sk_buff *skb)
       {
               int index;
               long *value;
               u8 *cursor = 0;

               if (skb->pkt_type != PACKET_OUTGOING)
                       return 0;

               // ★（2）パケットデータへのアクセス
               struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
               if (!(ethernet->type == 0x0800)) {
                       return 0;
               }

               struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
               index = ip->nextp;

               // ★（3）BPFマップのアクセス
               value = my_map.lookup(&index);
               if (value)
                       lock_xadd(value, skb->len);
               return 0;
}
"""

PROTO = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
}


def main(interface="lo", debug=0):
    # （4）BPFプログラムのロード
    bpf = BPF(text=prog, debug=debug)
    bpf_prog = bpf.load_func("bpf_prog", BPF.SOCKET_FILTER)

    # （5）BPFプログラムのアタッチ
    BPF.attach_raw_socket(bpf_prog, interface)
    my_map = bpf.get_table("my_map")

    devnull = open(os.devnull, "w")
    p = subprocess.Popen(
        ["/bin/ping", "-4", "-c5", "localhost"], stdout=devnull)

    for _ in range(5):
        # (6) BPFマップへのアクセス
        print("TCP {} UDP {} ICMP {} bytes".format(
            my_map[ct.c_int(
                PROTO["TCP"])].value,
            my_map[ct.c_int(
                PROTO["UDP"])].value,
            my_map[ct.c_int(PROTO["ICMP"])].value))
        time.sleep(1)

        p.wait()

        if __name__ == "__main__":
            import argparse
            parser = argparse.ArgumentParser()
            parser.add_argument("--interface", default="lo")
            parser.add_argument("--debug", default=0)
            args = parser.parse_args()
            main(args.interface, args.debug)
