#!/usr/bin/env python3
import math
import struct
import sys


def mulaw(sample):
    bias = 0x84
    sign = 0x80 if sample < 0 else 0
    sample = min(abs(sample), 32635) + bias
    exponent = 7
    mask = 0x4000
    while exponent > 0 and not (sample & mask):
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return ~(sign | (exponent << 4) | mantissa) & 0xFF


def main():
    out = sys.argv[1]
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    rate = 8000
    data = bytes(mulaw(int(8000 * math.sin(2 * math.pi * 440 * n / rate))) for n in range(int(rate * seconds)))
    fmt = struct.pack("<HHIIHHH", 7, 1, rate, rate, 1, 8, 0)
    riff = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"fact" + struct.pack("<II", 4, len(data)) + b"data" + struct.pack("<I", len(data)) + data
    with open(out, "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", len(riff)) + riff)


if __name__ == "__main__":
    main()
