#!/usr/bin/env python3
import collections
import subprocess
import sys


def main():
    pcap = sys.argv[1]
    exclude = {22222, 5060, 5070, 5080, 53}
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "udp", "-T", "fields", "-e", "ip.src", "-e", "udp.srcport",
         "-e", "ip.dst", "-e", "udp.dstport", "-e", "ip.id", "-e", "udp.payload"],
        check=True, capture_output=True, text=True).stdout
    seen = set()
    counts = collections.Counter()
    for line in out.splitlines():
        src, sport, dst, dport, ipid, payload = (line.split("\t") + [""])[:6]
        if int(sport) in exclude or int(dport) in exclude or len(payload) < 4:
            continue
        key = (src, sport, dst, dport, ipid)
        if key in seen:
            continue
        seen.add(key)
        raw = bytes.fromhex(payload.replace(":", ""))
        if raw[0] >> 6 != 2:
            continue
        counts[(f"{src}:{sport}", f"{dst}:{dport}", raw[1] & 0x7F)] += 1
    for (src, dst, pt), n in sorted(counts.items()):
        print(f"{src:22} -> {dst:22} pt={pt:3} packets={n}")


if __name__ == "__main__":
    main()
