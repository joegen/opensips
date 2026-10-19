#!/usr/bin/env python3
import subprocess
import sys


def packets(pcap, exclude_ports=(22222, 5060, 5070, 5080, 53)):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "udp", "-T", "fields", "-e", "frame.time_relative",
         "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport", "-e", "ip.id"],
        check=True, capture_output=True, text=True).stdout
    seen = set()
    for line in out.splitlines():
        t, src, sport, dst, dport, ipid = line.split("\t")
        sport, dport = int(sport), int(dport)
        if sport in exclude_ports or dport in exclude_ports:
            continue
        key = (src, sport, dst, dport, ipid)
        if key in seen:
            continue
        seen.add(key)
        yield float(t), f"{src}:{sport}", f"{dst}:{dport}"


def main():
    pcap = sys.argv[1]
    flows = {}
    for t, src, dst in packets(pcap):
        f = flows.setdefault((src, dst), [t, t, 0])
        f[1] = t
        f[2] += 1
    for (src, dst), (first, last, n) in sorted(flows.items(), key=lambda x: x[1][0]):
        print(f"{src:22} -> {dst:22} packets={n:5} first={first:8.3f} last={last:8.3f}")


if __name__ == "__main__":
    main()
