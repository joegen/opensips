#!/usr/bin/env python3
import sys

from rtp_flows import packets


def main():
    pcap = sys.argv[1]
    lo, hi = 40000, 49999
    segments = {}
    gaps = {}
    last_seen = {}
    for t, src, dst in sorted(packets(pcap)):
        sport = int(src.rsplit(":", 1)[1])
        if lo <= sport <= hi:
            segs = segments.setdefault(src, [])
            if segs and segs[-1][0] == dst:
                segs[-1][2] = t
                segs[-1][3] += 1
            else:
                segs.append([dst, t, t, 1])
        else:
            key = (src, dst)
            if key in last_seen and t - last_seen[key] > 0.5:
                gaps.setdefault(key, []).append((last_seen[key], t))
            last_seen[key] = t
    for src, segs in segments.items():
        for dst, first, last, n in segs:
            print(f"rtpengine {src:22} -> {dst:22} first={first:8.3f} last={last:8.3f} packets={n}")
    for (src, dst), spans in gaps.items():
        for a, b in spans:
            print(f"silent    {src:22} -> {dst:22} from={a:8.3f} to={b:8.3f}")


if __name__ == "__main__":
    main()
