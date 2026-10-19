#!/usr/bin/env python3
import re
import sys


def messages(path):
    text = open(path, errors="replace").read()
    blocks = re.split(r"\n(?=-{10,}|\S+ message (?:sent|received))", text)
    out = []
    for b in blocks:
        m = re.search(r"^(INVITE|ACK|BYE|SIP/2\.0 \d+)[^\n]*", b, re.M)
        if m:
            out.append((m.group(0), b))
    return out


def body(b):
    parts = re.split(r"\r?\n\r?\n", b, maxsplit=1)
    return parts[1] if len(parts) > 1 else ""


def rtpengine_port(sdp):
    m = re.search(r"^m=audio (\d+) ", sdp, re.M)
    port = int(m.group(1)) if m else 0
    return 40000 <= port <= 49999 and port not in (6000, 6050)


def main():
    res_dir = sys.argv[1]
    rtpe_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.19"
    ok = True
    uas = messages(f"{res_dir}/uas_messages.log")
    uac = messages(f"{res_dir}/uac_messages.log")
    inv = next(b for first, b in uas if first.startswith("INVITE") and "CSeq: 1 INVITE" in b)
    sdp = body(inv)
    checks = {
        "Content-Type application/sdp": re.search(r"^Content-Type: application/sdp", inv, re.M) is not None,
        "exactly one Content-Type": len(re.findall(r"^Content-Type:", inv, re.M | re.I)) == 1,
        "m= port is an RTPEngine port": rtpengine_port(sdp),
        "m=audio RTP/AVP 0 8 9 101": re.search(r"^m=audio \d+ RTP/AVP 0 8 9 101\s*$", sdp, re.M) is not None,
        "rtpmap 0/8/9/101 (G722/8000)": all(x in sdp for x in ("a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000", "a=rtpmap:9 G722/8000", "a=rtpmap:101 telephone-event/8000")),
        "fmtp:101 0-15": "a=fmtp:101 0-15" in sdp,
        "a=sendrecv": "a=sendrecv" in sdp,
        "no a=crypto": "a=crypto" not in sdp,
        "no ICE/DTLS": not re.search(r"a=(ice-|candidate|fingerprint|setup:|tls-id)", sdp),
        f"c= = RTPEngine {rtpe_ip}": f"c=IN IP4 {rtpe_ip}" in sdp,
    }
    ok200 = next(b for first, b in uac if first.startswith("SIP/2.0 200") and "CSeq: 1 INVITE" in b)
    s200 = body(ok200)
    checks["UAC 200 RTP/AVP"] = re.search(r"^m=audio \d+ RTP/AVP ", s200, re.M) is not None
    checks[f"UAC 200 c= = RTPEngine {rtpe_ip}"] = f"c=IN IP4 {rtpe_ip}" in s200
    checks["UAC 200 m= port is an RTPEngine port"] = rtpengine_port(s200)
    ack = next(b for first, b in uas if first.startswith("ACK") and "CSeq: 1 ACK" in b)
    checks["UAS ACK no Content-Type"] = re.search(r"^Content-Type:", ack, re.M) is None
    checks["UAS ACK Content-Length 0"] = re.search(r"^Content-Length: *0\s*$", ack, re.M) is not None and not body(ack).lstrip().startswith("v=")
    for k, v in checks.items():
        print(("PASS " if v else "FAIL ") + k)
        ok &= v
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
