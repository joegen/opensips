#!/usr/bin/env python3
import struct
import sys


def rtp(seq, ts, ssrc, pt, marker, payload):
    b0 = 0x80
    b1 = (0x80 if marker else 0) | pt
    return struct.pack("!BBHII", b0, b1, seq, ts, ssrc) + payload


def event(digit, end, volume, duration):
    return struct.pack("!BBH", digit, (0x80 if end else 0) | volume, duration)


def udp_ip_eth(payload, sport=6060, dport=6060):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + udp


def main():
    out, pt, digit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    ssrc, seq, ts0 = 0x4733DDDD, 1000, 160000
    packets = []
    t = 0.0
    for i, dur in enumerate(range(160, 1280, 160)):
        packets.append((t, rtp(seq, ts0, ssrc, pt, i == 0, event(digit, False, 10, dur))))
        seq += 1
        t += 0.02
    for _ in range(3):
        packets.append((t, rtp(seq, ts0, ssrc, pt, False, event(digit, True, 10, 1280))))
        seq += 1
        t += 0.02
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, p in packets:
            frame = udp_ip_eth(p)
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)


if __name__ == "__main__":
    main()
