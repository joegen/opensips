#!/usr/bin/env python3
import subprocess
import sys


def bdecode(data, i=0):
    c = data[i:i + 1]
    if c == b"d":
        i += 1
        out = {}
        while data[i:i + 1] != b"e":
            key, i = bdecode(data, i)
            val, i = bdecode(data, i)
            out[key.decode(errors="replace")] = val
        return out, i + 1
    if c == b"l":
        i += 1
        out = []
        while data[i:i + 1] != b"e":
            val, i = bdecode(data, i)
            out.append(val)
        return out, i + 1
    if c == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1:end]), end + 1
    colon = data.index(b":", i)
    n = int(data[i:colon])
    start = colon + 1
    return data[start:start + n], start + n


def text(v):
    return v.decode(errors="replace") if isinstance(v, bytes) else v


def messages(pcap, port=22222):
    fields = subprocess.run(
        ["tshark", "-r", pcap, "-Y", f"udp.port=={port}", "-T", "fields",
         "-e", "frame.time_relative", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
        check=True, capture_output=True, text=True).stdout
    for line in fields.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3]:
            continue
        raw = bytes.fromhex(parts[3].replace(":", ""))
        cookie, _, payload = raw.partition(b" ")
        try:
            body, _ = bdecode(payload)
        except (ValueError, IndexError):
            continue
        direction = "req" if int(parts[2]) == port else "rsp"
        yield float(parts[0]), direction, cookie.decode(errors="replace"), body


def main():
    pcap = sys.argv[1]
    call_id = sys.argv[2] if len(sys.argv) > 2 else None
    pending = {}
    for t, direction, cookie, body in messages(pcap):
        if direction == "req":
            pending[cookie] = body
            cmd = text(body.get("command"))
            cid = text(body.get("call-id", b""))
            if cmd == "ping" or (call_id and cid != call_id):
                continue
            print(f"{t:9.3f} {cmd:8} call-id={cid} from-tag={text(body.get('from-tag', b''))} "
                  f"to-tag={text(body.get('to-tag', b''))} flags={[text(x) for x in body.get('flags', [])]}")
        else:
            req = pending.pop(cookie, {})
            cmd = text(req.get("command"))
            cid = text(req.get("call-id", b""))
            if cmd == "ping" or (call_id and cid != call_id):
                continue
            print(f"{t:9.3f}   -> {cmd} result={text(body.get('result'))}")


if __name__ == "__main__":
    main()
