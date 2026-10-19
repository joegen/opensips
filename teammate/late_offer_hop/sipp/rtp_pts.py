#!/usr/bin/env python3
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rtp_flows import packets


def main():
    counts = collections.Counter()
    for _, src, dst, payload in packets(sys.argv[1], with_payload=True):
        if len(payload) < 4:
            continue
        raw = bytes.fromhex(payload.replace(":", ""))
        if raw[0] >> 6 != 2:
            continue
        counts[(src, dst, raw[1] & 0x7F)] += 1
    for (src, dst, pt), n in sorted(counts.items()):
        print(f"{src:22} -> {dst:22} pt={pt} packets={n}")


if __name__ == "__main__":
    main()
