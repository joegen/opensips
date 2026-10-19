#!/usr/bin/env python3
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ng_log import messages as ng_messages, text
from rtp_flows import packets

MEDIA_IP = "192.168.1.19"
UAS_PORT = 6000
UAC_PORT = 6050
ADVERTISED_IP = "203.0.113.10"
HOP_PORT = 5080
UAS_SIP_PORT = 5060


def sip_messages(path):
    if not os.path.exists(path):
        return []
    out = []
    for block in re.split(r"^-{10,}[^\n]*\n", open(path, errors="replace").read(), flags=re.M):
        head, _, msg = block.partition("\n\n")
        if "message" not in head:
            continue
        out.append(("received" in head, msg.replace("\r", "")))
    return out


def first_line(msg):
    return msg.split("\n", 1)[0]


def header(msg, name):
    m = re.search(rf"^{name}:\s*(.*)$", msg, re.M | re.I)
    return m.group(1) if m else None


def body(msg):
    parts = msg.split("\n\n", 1)
    return parts[1].strip() if len(parts) > 1 else ""


def received(msgs, start, cseq=None):
    return [m for r, m in msgs if r and first_line(m).startswith(start) and (cseq is None or header(m, "CSeq") == cseq)]


def sdp_port(msg):
    m = re.search(r"^m=audio (\d+) ", body(msg), re.M)
    return int(m.group(1)) if m else None


def origin_match(msg):
    return re.search(r"^o=(\S+) (\d+) (\d+) (?:IN IP4 (\S+)$)?", body(msg), re.M)


def origin(msg):
    m = origin_match(msg)
    return (m.group(1), m.group(2), int(m.group(3))) if m else None


def origin_addr(msg):
    m = origin_match(msg)
    return m.group(4) if m else None


class Case:
    def __init__(self, d):
        self.d = d
        self.uac = sip_messages(f"{d}/uac_messages.log")
        self.uas = sip_messages(f"{d}/uas_messages.log")
        sent = [m for r, m in self.uac if not r and first_line(m).startswith("INVITE")]
        self.call_ids = sorted({header(m, "Call-ID") for r, m in self.uac if not r and not first_line(m).startswith("SIP/2.0")})
        self.uac_tag = None
        if sent:
            m = re.search(r"tag=([^;>\s]+)", header(sent[0], "From") or "")
            self.uac_tag = m.group(1) if m else None
        self._ng = None
        self._rtp = None
        self._frames = None

    def ng(self):
        if self._ng is None:
            pending, out, seen = {}, [], set()
            for t, direction, cookie, b in ng_messages(f"{self.d}/capture.pcap"):
                if direction == "req":
                    pending[cookie] = b
                    if text(b.get("command")) == "ping" or text(b.get("call-id", b"")) not in self.call_ids:
                        continue
                    if cookie in seen:
                        continue
                    seen.add(cookie)
                    out.append({"t": t, "cmd": text(b.get("command")), "from": text(b.get("from-tag", b"")),
                                "flags": [text(x) for x in b.get("flags", [])], "cookie": cookie, "result": None})
                else:
                    for c in out:
                        if c["cookie"] == cookie and c["result"] is None:
                            c["result"] = text(b.get("result"))
            self._ng = out
        return self._ng

    def cmds(self):
        return [c["cmd"] for c in self.ng()]

    def rtp(self):
        if self._rtp is None:
            self._rtp = sorted(p for p in packets(f"{self.d}/capture.pcap")
                               if p[1].startswith(MEDIA_IP + ":") and p[2].startswith(MEDIA_IP + ":"))
        return self._rtp

    def call_id_filter(self):
        return " or ".join(f'sip.Call-ID == "{cid}"' for cid in self.call_ids)

    def sip_in_capture(self):
        if not self.call_ids:
            return 0
        out = subprocess.run(["tshark", "-r", f"{self.d}/capture.pcap", "-Y", self.call_id_filter(), "-T", "fields", "-e", "frame.number"],
                             check=True, capture_output=True, text=True).stdout
        return len(out.split())

    def sip_frames(self):
        if self._frames is None:
            self._frames = []
            if self.call_ids:
                fields = ["sll.pkttype", "ip.src", "udp.srcport", "tcp.srcport", "ip.dst", "udp.dstport", "tcp.dstport", "tcp.stream",
                          "sip.Method", "sip.Status-Code", "sip.CSeq.method", "sip.Call-ID"]
                cmd = ["tshark", "-r", f"{self.d}/capture.pcap", "-o", "tcp.analyze_sequence_numbers:FALSE", "-Y", self.call_id_filter(),
                       "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
                for f in fields:
                    cmd += ["-e", f]
                out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
                for line in out.splitlines():
                    pkttype, *v = line.split("|")
                    if pkttype != "0":
                        continue
                    self._frames.append({"src": v[0], "sport": int(v[1] or v[2]), "dst": v[3], "dport": int(v[4] or v[5]),
                                         "stream": v[6], "method": v[7], "status": v[8], "cseq": v[9], "cid": v[10]})
        return self._frames


def port_of(addr):
    return int(addr.rsplit(":", 1)[1])


def gaps(c, src_port, min_gap=0.5):
    times = [t for t, s, d in c.rtp() if port_of(s) == src_port and not 40000 <= port_of(s) <= 49999]
    return [(a, b) for a, b in zip(times, times[1:]) if b - a > min_gap]


def rtpe_to(c, dst_port):
    return [t for t, s, d in c.rtp() if 40000 <= port_of(s) <= 49999 and port_of(d) == dst_port]


def silent_window(c, moved, home):
    sent = rtpe_to(c, moved)
    if not sent:
        return False, f"no RTP to :{moved}"
    first = sent[0]
    for a, b in gaps(c, home):
        if a <= first <= b:
            return True, f"RTPEngine to :{moved} at {first:.3f} inside silent {a:.3f}-{b:.3f}"
    return False, f"RTPEngine to :{moved} at {first:.3f} not inside a silent window of :{home}"


PEER_PORTS = {UAS_PORT: (UAS_PORT, 6048, 6097), UAC_PORT: (UAC_PORT, 6098)}


def dest_after_resume(c, home):
    out = []
    for a, b in gaps(c, home):
        dst = [port_of(d) for t, s, d in c.rtp()
               if 40000 <= port_of(s) <= 49999 and b < t < b + 0.2 and port_of(d) in PEER_PORTS[home]]
        out.append((b, dst))
    return out


def recovered(dst, home):
    return home in dst and all(d == home for d in dst[1:])


def chk(results, name, ok, detail=""):
    results.append((name, bool(ok), detail))


def t01(c, r):
    p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_t01.py"), c.d],
                       capture_output=True, text=True)
    chk(r, "check_t01", p.returncode == 0, p.stdout.count("PASS") and f"{p.stdout.count('PASS')}/{p.stdout.count('PASS') + p.stdout.count('FAIL')}")


def ng_zero(c, r):
    n = c.sip_in_capture()
    chk(r, "capture holds the call's SIP", n > 0, f"{n} SIP packets")
    chk(r, "no NG command", c.cmds() == [], c.cmds())


def t03(c, r):
    ids = [origin(m)[1] for m in received(c.uas, "INVITE", "1 INVITE") if origin(m)]
    chk(r, "two o= session ids", len(ids) == 2, ids)
    chk(r, "distinct", len(set(ids)) == 2)
    chk(r, "^[0-9]{1,18}$", all(re.fullmatch(r"[0-9]{1,18}", i) for i in ids))


def t04(c, r):
    inv = received(c.uas, "INVITE", "1 INVITE")
    rr = header(inv[0], "Record-Route") if inv else ""
    chk(r, "Record-Route ;lo-conv=1 and ftag", rr and ";lo-conv=1" in rr and "ftag=" in rr, rr)
    deletes = [x for x in c.ng() if x["cmd"] == "delete"]
    chk(r, "one delete, flag fast, reply ok", len(deletes) == 1 and deletes[0]["flags"] == ["fast"] and deletes[0]["result"] == "ok",
        [(x["flags"], x["result"]) for x in deletes])
    bye = [m for rr_, m in c.uas + c.uac if rr_ and first_line(m).startswith("BYE")]
    chk(r, "BYE passed the hop", len(bye) >= 1)


def t06(c, r):
    cmds = c.ng()
    chk(r, "offer, answer, answer, delete", [x["cmd"] for x in cmds] == ["offer", "answer", "answer", "delete"], c.cmds())
    if len(cmds) >= 2:
        chk(r, "S3 answer from-tag = UAC tag", cmds[1]["from"] == c.uac_tag, (cmds[1]["from"], c.uac_tag))


def t07(c, r):
    inv = received(c.uas, "INVITE")
    chk(r, "two INVITEs at the UAS", len(inv) == 2)
    if len(inv) == 2:
        o1, o2 = origin(inv[0]), origin(inv[1])
        chk(r, "Mediant-facing port unchanged", sdp_port(inv[0]) == sdp_port(inv[1]), (sdp_port(inv[0]), sdp_port(inv[1])))
        chk(r, "o= username and session id unchanged", o1 and o2 and o1[:2] == o2[:2], (o1, o2))
        chk(r, "re-offer lists 0 8 9 101 sendrecv", re.search(r"^m=audio \d+ RTP/AVP 0 8 9 101$", body(inv[1]), re.M) and "a=sendrecv" in body(inv[1]))
    to_uac = rtpe_to(c, UAC_PORT)
    from_uac = [t for t, s, d in c.rtp() if port_of(s) == UAC_PORT]
    chk(r, "RTPEngine sends to the UAC before the UAC sends", to_uac and from_uac and to_uac[0] < from_uac[0],
        (to_uac[:1], from_uac[:1]))


def t08_ack_body(c, r, side):
    msgs = c.uas if side == "uas" else c.uac
    acks = received(msgs, "ACK", "2 ACK") if side == "uas" else received(msgs, "ACK")
    with_body = [a for a in acks if body(a).startswith("v=0")]
    chk(r, f"S7 ACK relayed with RTPEngine's body to the {side}", len(with_body) >= 1)


def s7_ng(c, r):
    chk(r, "S7 NG offer on the 200 and answer on the ACK", c.cmds()[3:5] == ["offer", "answer"], c.cmds())


def t09r1(c, r):
    s7_ng(c, r)
    t08_ack_body(c, r, "uas")
    chk(r, "silent window :6097", *silent_window(c, 6097, UAS_PORT))


def t09r2(c, r):
    s7_ng(c, r)
    t08_ack_body(c, r, "uas")
    chk(r, "silent window :6098", *silent_window(c, 6098, UAC_PORT))
    inv = received(c.uas, "INVITE", "1 INVITE")
    ack = [a for a in received(c.uas, "ACK", "2 ACK") if body(a)]
    if inv and ack:
        chk(r, "UAS ACK answer: Mediant-facing port and o= id unchanged",
            sdp_port(ack[0]) == sdp_port(inv[0]) and origin(ack[0])[:2] == origin(inv[0])[:2])


def t10r1(c, r):
    s7_ng(c, r)
    t08_ack_body(c, r, "uac")
    chk(r, "silent window :6098", *silent_window(c, 6098, UAC_PORT))
    inv = received(c.uas, "INVITE", "1 INVITE")
    ok200 = [m for m in received(c.uas, "SIP/2.0 200") if header(m, "CSeq") == "1 INVITE" and body(m)]
    if inv and ok200:
        chk(r, "UAS 200 offer: Mediant-facing port and o= id unchanged",
            sdp_port(ok200[-1]) == sdp_port(inv[0]) and origin(ok200[-1])[:2] == origin(inv[0])[:2])


def t10r2(c, r):
    s7_ng(c, r)
    t08_ack_body(c, r, "uac")
    chk(r, "silent window :6097", *silent_window(c, 6097, UAS_PORT))


def t11_noreoffer(c, r):
    reinv = [m for rr_, m in c.uas + c.uac if rr_ and first_line(m).startswith("INVITE") and header(m, "CSeq") != "1 INVITE" and not body(m)]
    chk(r, "a body-less re-INVITE crossed the hop", len(reinv) >= 1)
    chk(r, "no NG for the rejected body-less re-INVITE", c.cmds() == ["offer", "answer", "answer", "delete"], c.cmds())
    segs = {}
    for t, s, d in c.rtp():
        if 40000 <= port_of(s) <= 49999:
            segs.setdefault(s, set()).add(d)
    chk(r, "media unchanged (one destination per RTPEngine port)", all(len(v) == 1 for v in segs.values()), segs)


def t11_retr(c, r):
    chk(r, "S7 offer/answer run again for the retransmissions", c.cmds().count("offer") >= 3, c.cmds())
    segs = {}
    for t, s, d in c.rtp():
        if 40000 <= port_of(s) <= 49999:
            segs.setdefault(s, set()).add(d)
    chk(r, "no port change", all(len(v) == 1 for v in segs.values()) and len(segs) == 2, segs)


def t11_down(c, r):
    ok200 = [m for m in received(c.uac, "SIP/2.0 200") if header(m, "CSeq") == "2 INVITE"]
    chk(r, "re-INVITE 200 reaches the UAC without body", ok200 and all(not body(m) for m in ok200), len(ok200))
    ack = received(c.uas, "ACK", "2 ACK")
    chk(r, "ACK reaches the UAS without body", ack and all(not body(m) for m in ack), len(ack))


def t11_downack(c, r):
    ok200 = [m for m in received(c.uac, "SIP/2.0 200") if header(m, "CSeq") == "2 INVITE"]
    chk(r, "first re-INVITE 200 carries SDP, a later retransmission has none",
        len(ok200) >= 2 and body(ok200[0]).startswith("v=0") and any(not body(m) for m in ok200[1:]), [bool(body(m)) for m in ok200])
    ack = received(c.uas, "ACK", "2 ACK")
    chk(r, "the CSeq 2 ACK with the answer reaches the UAS without body", ack and all(not body(m) for m in ack), len(ack))


def t14(c, r):
    inv = received(c.uas, "INVITE")
    ports = {sdp_port(m) for m in inv}
    chk(r, "Mediant-facing port unchanged over 3 INVITEs", len(inv) == 3 and len(ports) == 1, ports)
    chk(r, "hold offer is sendonly", len(inv) == 3 and "a=sendonly" in body(inv[1]))
    chk(r, "silent window :6098", *silent_window(c, 6098, UAC_PORT))


def deleted(c, r, final=None):
    chk(r, "offer then delete", c.cmds()[:1] == ["offer"] and c.cmds()[-1:] == ["delete"], c.cmds())
    if final:
        got = [first_line(m) for m in received(c.uac, "SIP/2.0 ") if header(m, "CSeq") == "1 INVITE"]
        chk(r, f"UAC gets {final}", any(g.startswith(f"SIP/2.0 {final}") for g in got), got)


def t18(c, r):
    chk(r, "silent window :6098", *silent_window(c, 6098, UAC_PORT))
    chk(r, "silent window :6048", *silent_window(c, 6048, UAS_PORT))
    inv = received(c.uas, "INVITE")
    os_ = [origin(m) for m in inv]
    chk(r, "UAS sees 3 INVITE offers, same o= id and Mediant-facing port",
        len(inv) == 3 and len({o[:2] for o in os_}) == 1 and len({sdp_port(m) for m in inv}) == 1, os_)
    if len(os_) == 3:
        v = [o[2] for o in os_]
        chk(r, "T-19 versions: V, V+1 or V+2, then unchanged", v[1] in (v[0] + 1, v[0] + 2) and v[2] == v[1], v)


def t20_recovery(c, r, home):
    res = dest_after_resume(c, home)
    chk(r, f"after the offerer resumes, RTPEngine sends to :{home} (only the first packet may still go to the old port)",
        res and all(recovered(d, home) for b, d in res), res)
    inv = received(c.uas, "INVITE")
    chk(r, "Mediant-facing port unchanged", len({sdp_port(m) for m in inv if sdp_port(m)}) == 1)


def t20_488u(c, r):
    chk(r, "offer for the rejected re-INVITE, no answer", c.cmds() == ["offer", "answer", "answer", "offer", "delete"], c.cmds())
    t20_recovery(c, r, UAC_PORT)


def t20_488s(c, r):
    chk(r, "offer for the rejected re-INVITE, no answer", c.cmds() == ["offer", "answer", "answer", "offer", "delete"], c.cmds())
    t20_recovery(c, r, UAS_PORT)


def t20cancel(c, r):
    chk(r, "offer for the cancelled re-INVITE, no answer", c.cmds() == ["offer", "answer", "answer", "offer", "delete"], c.cmds())
    got = [first_line(m) for m in received(c.uac, "SIP/2.0 487")]
    chk(r, "UAC gets 487", len(got) >= 1)
    t20_recovery(c, r, UAC_PORT)


def t20g1(c, r):
    chk(r, "glare offers, retries offer/answer", c.cmds() == ["offer", "answer", "answer", "offer", "offer", "offer", "answer", "offer", "answer", "delete"], c.cmds())
    t20_recovery(c, r, UAC_PORT)


def t20g2(c, r):
    chk(r, "glare offer, retries offer/answer", c.cmds() == ["offer", "answer", "answer", "offer", "offer", "answer", "offer", "answer", "delete"], c.cmds())
    t20_recovery(c, r, UAS_PORT)


def t22(c, r):
    cancel_ok = [m for m in received(c.uac, "SIP/2.0 200") if header(m, "CSeq") == "1 CANCEL"]
    chk(r, "the UAC's CANCEL was answered 200", len(cancel_ok) == 1)
    chk(r, "no delete before the BYE (delete only last, once)", c.cmds().count("delete") == 1 and c.cmds()[-1] == "delete", c.cmds())
    chk(r, "offer, S3 answer, S4 answer", c.cmds()[:3] == ["offer", "answer", "answer"], c.cmds())
    ok200 = [m for m in received(c.uac, "SIP/2.0 200") if header(m, "CSeq") == "1 INVITE"]
    chk(r, "UAC 200 carries RTPEngine's offer", ok200 and 40000 <= (sdp_port(ok200[0]) or 0) <= 49999)
    ack = received(c.uas, "ACK", "1 ACK")
    chk(r, "ACK at the UAS has no body and no Content-Type", ack and not body(ack[0]) and header(ack[0], "Content-Type") is None)


def t22b(c, r):
    t22(c, r)
    chk(r, "the CANCEL reached the UAS", len(received(c.uas, "CANCEL")) == 1)


def t23(c, r):
    chk(r, "offer, delete, offer (fresh), then S3/S4 answers", c.cmds()[:3] == ["offer", "delete", "offer"] and c.cmds()[3:5] == ["answer", "answer"], c.cmds())
    inv = received(c.uas, "INVITE", "2 INVITE")
    rr = header(inv[0], "Record-Route") if inv else ""
    chk(r, "retry carries ;lo-conv=2", rr and ";lo-conv=2" in rr, rr)
    ack = received(c.uas, "ACK", "2 ACK")
    chk(r, "retry ACK at the UAS has no body (S4 ran)", ack and not body(ack[0]))


def t27_28(c, r):
    ng_zero(c, r)
    sent = [m for rr_, m in c.uac if not rr_ and first_line(m).startswith("INVITE")]
    got = received(c.uas, "INVITE", "1 INVITE")
    chk(r, "INVITE body byte-identical at the UAS", sent and got and body(sent[0]) == body(got[0]))


def event_pts_to_uas(c):
    from rtp_flows import packets as pk
    pts = {}
    for _, src, dst, payload in pk(f"{c.d}/capture.pcap", with_payload=True):
        if not dst.endswith(f":{UAS_PORT}") or len(payload) < 4:
            continue
        raw = bytes.fromhex(payload.replace(":", ""))
        if raw[0] >> 6 == 2 and (raw[1] & 0x7F) != 0:
            pts[raw[1] & 0x7F] = pts.get(raw[1] & 0x7F, 0) + 1
    return pts


def t21a(c, r):
    pts = event_pts_to_uas(c)
    chk(r, "no event packets toward the UAS (the UAC declared none and sends none)", pts == {}, pts)


def t21b(c, r):
    pts = event_pts_to_uas(c)
    chk(r, "toward the UAS only PT 101, 10 packets", pts == {101: 10}, pts)


def t29(c, r):
    got = [first_line(m) for m in received(c.uac, "SIP/2.0 ") if header(m, "CSeq") == "1 INVITE"]
    chk(r, "UAC gets 500", any(g.startswith("SIP/2.0 500") for g in got), got)
    chk(r, "nothing reaches the UAS", not any(rr_ for rr_, m in c.uas))


def t29b(c, r):
    t29(c, r)
    chk(r, "NG offer then delete", c.cmds() == ["offer", "delete"], c.cmds())


def t30(c, r):
    ok200 = [m for m in received(c.uac, "SIP/2.0 200") if header(m, "CSeq") == "1 INVITE"]
    b = body(ok200[0]) if ok200 else ""
    chk(r, "UAC 2xx lists exactly 0 9 101 on an RTPEngine port", re.search(r"^m=audio 4\d{4} RTP/AVP 0 9 101$", b, re.M))
    chk(r, "rtpmap 0/9/101 and fmtp:101 0-15, no ICE", all(x in b for x in ("a=rtpmap:0 PCMU/8000", "a=rtpmap:9 G722/8000", "a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-15")) and "a=ice" not in b and "a=candidate" not in b)
    chk(r, "S4 NG command", c.cmds()[:3] == ["offer", "answer", "answer"], c.cmds())
    ack = received(c.uas, "ACK", "1 ACK")
    chk(r, "ACK at the UAS has no body and no Content-Type", ack and not body(ack[0]) and header(ack[0], "Content-Type") is None)


def t32(c, r):
    chk(r, "NG: S1/S3/S4, offer+answer per UPDATE with SDP, none for body-less UPDATEs",
        c.cmds() == ["offer", "answer", "answer", "offer", "answer", "offer", "answer", "delete"], c.cmds())


def t17(c, r):
    chk(r, "offer, answer, answer, delete", c.cmds() == ["offer", "answer", "answer", "delete"], c.cmds())
    ack = received(c.uas, "ACK", "1 ACK")
    chk(r, "ACK at the UAS has no body", ack and not body(ack[0]))


def c_lines(msg):
    return re.findall(r"^c=IN IP4 (\S+)$", body(msg), re.M)


def t37(c, r):
    inv = received(c.uas, "INVITE", "1 INVITE")
    ok = received(c.uac, "SIP/2.0 200", "1 INVITE")
    cs = [x for m in inv[:1] + ok[:1] for x in c_lines(m)]
    chk(r, "INVITE at the UAS and 200 at the UAC each carry c=, every c= is the advertised address",
        inv and ok and c_lines(inv[0]) and c_lines(ok[0]) and all(x == ADVERTISED_IP for x in cs), cs)
    o = origin_addr(inv[0]) if inv else None
    chk(r, "o= address in the INVITE at the UAS is the advertised address", o == ADVERTISED_IP, o)
    ports = sorted({p for p in map(sdp_port, inv[:1] + ok[:1]) if p})
    path = f"{c.d}/ss_samples.txt"
    ss = open(path).read() if os.path.exists(path) else ""
    bound = {int(a.rsplit(":", 1)[1]): a.rsplit(":", 1)[0] for a in re.findall(r"\s(\d+\.\d+\.\d+\.\d+:\d+)\s", ss)}
    chk(r, "the call's RTPEngine media ports were bound on the bed address during the call",
        len(ports) == 2 and all(bound.get(p) == MEDIA_IP for p in ports), {p: bound.get(p) for p in ports})
    chk(r, "nothing bound on the advertised address", ss and ADVERTISED_IP not in ss)


def rejected(c, r, methods, code):
    f = c.sip_frames()
    to_hop = [x for x in f if x["dport"] == HOP_PORT and x["method"]]
    from_hop = [x for x in f if x["sport"] == HOP_PORT and x["status"]]
    for m in methods:
        reqs = [x for x in to_hop if x["method"] == m]
        resp = [x for x in from_hop if x["cseq"] == m]
        rc = [x for x in resp if x["status"] == code]
        chk(r, f"capture holds the {m} to the hop and the hop's {code}", reqs and rc, f"{len(reqs)} {m}, {len(rc)} {code}")
        chk(r, f"exactly one {code} per copy of the {m} the hop received", len(reqs) == len(rc), f"{len(reqs)} vs {len(rc)}")
        chk(r, f"the hop sends no other response to the {m}", all(x["status"] == code for x in resp),
            sorted({x["status"] for x in resp}))
    if "INVITE" in methods:
        chk(r, f"the ACK of the {code} is in the capture toward the hop", any(x["method"] == "ACK" for x in to_hop))
    chk(r, "no request with the row's Call-IDs reaches the UAS (ACK included)",
        not any(x["dport"] == UAS_SIP_PORT and x["method"] for x in f), [x["method"] for x in f if x["dport"] == UAS_SIP_PORT])
    chk(r, "UAS log holds no message", not c.uas)
    chk(r, "no NG command", c.cmds() == [], c.cmds())


def karoo_ip_lines(path):
    return [l.strip() for l in open(path) if "lo_karoo_" in l and "_ip)" in l] if os.path.exists(path) else []


def same_connection(c, r, code):
    f = c.sip_frames()
    streams = {x["stream"] for x in f if x["method"] == "INVITE" and x["dport"] == HOP_PORT} | \
              {x["stream"] for x in f if x["status"] == code and x["sport"] == HOP_PORT}
    chk(r, f"the {code} comes back on the INVITE's TCP connection", len(streams) == 1 and "" not in streams, streams)


def t38udp(c, r):
    rejected(c, r, ["INVITE", "OPTIONS"], "482")


def t38tcp(c, r):
    rejected(c, r, ["INVITE"], "482")
    same_connection(c, r, "482")
    sipp_lines = karoo_ip_lines(os.path.join(HERE, "..", "opensips", "late_offer_hop.local.cfg.sipp"))
    tcp_lines = karoo_ip_lines(f"{c.d}/late_offer_hop.local.cfg.tcp")
    chk(r, "the deployed TCP variant's lo_karoo_*_ip lines equal the .sipp lines", len(sipp_lines) == 2 and tcp_lines == sipp_lines, tcp_lines)


def naming_lines(c):
    path = f"{c.d}/opensips.log"
    log = open(path, errors="replace").read() if os.path.exists(path) else ""
    return [l for l in log.splitlines() if "naming the hop rejected with 404" in l and any(cid in l for cid in c.call_ids)]


def t39_rejected(c, r, methods, tcp=False):
    rejected(c, r, methods, "404")
    if tcp:
        same_connection(c, r, "404")
    chk(r, "the hop log holds the 'naming the hop' line for the Call-ID", naming_lines(c), len(naming_lines(c)))


def relayed(c, r, ruri):
    sent = [first_line(m) for rr_, m in c.uac if not rr_ and first_line(m).startswith("INVITE")]
    got = [first_line(m) for m in received(c.uas, "INVITE", "1 INVITE")]
    want = f"INVITE {ruri} SIP/2.0"
    chk(r, "the UAC sent the literal Request-URI", sent[:1] == [want], sent[:1])
    chk(r, "the UAS receives exactly that Request-URI", got[:1] == [want], got[:1])
    chk(r, "an NG offer is seen for the Call-ID", "offer" in c.cmds(), c.cmds())
    chk(r, "the hop log holds no 'naming the hop' line for the Call-ID", not naming_lines(c), len(naming_lines(c)))


def bed_ruri(c, r):
    sent = [first_line(m) for rr_, m in c.uac if not rr_ and first_line(m).startswith("INVITE")]
    chk(r, "the INVITE names the UAS in its Request-URI", sent[:1] == ["INVITE sip:late@192.168.1.19:5060 SIP/2.0"], sent[:1])
    to_hop = [x for x in c.sip_frames() if x["method"] == "INVITE" and x["dport"] == HOP_PORT and x["dst"] == MEDIA_IP]
    chk(r, "the INVITE is sent to the hop 192.168.1.19:5080 (capture)", to_hop, len(to_hop))


CHECKS = {
    "t01udp": t01, "t01tcp": t01, "t02a": t01, "t02b": t01,
    "t03seq": t03, "t03same": t03, "t04a": t04, "t04b": t04, "t05": ng_zero, "t06": t06,
    "t07": t07, "t07r": t07, "t09r1": t09r1, "t09r2": t09r2, "t10r1": t10r1, "t10r2": t10r2,
    "t11_488": t11_noreoffer, "t11_491": t11_noreoffer, "t11_retr": t11_retr, "t11_down": t11_down, "t11_downack": t11_downack,
    "t13b": ng_zero, "t14": t14,
    "t16cancel": lambda c, r: deleted(c, r, "487"), "t16_486": lambda c, r: deleted(c, r, "486"),
    "t16_603": lambda c, r: deleted(c, r, "603"), "t16to1": lambda c, r: deleted(c, r, "408"),
    "t16to2": lambda c, r: deleted(c, r, "408"), "t17": t17, "t18": t18,
    "t20_488u": t20_488u, "t20_488s": t20_488s, "t20cancel": t20cancel, "t20g1": t20g1, "t20g2": t20g2,
    "t22a": t22, "t22b": t22b, "t23_401": t23, "t23_422": t23, "t27": t27_28, "t28": t27_28,
    "t21a": t21a, "t21b": t21b, "t29": t29, "t29b": t29b, "t30": t30, "t32": t32,
    "t37": t37, "t38priv": t38udp, "t38pub": t38udp, "t38tcp": t38tcp,
    "t39a": lambda c, r: t39_rejected(c, r, ["INVITE", "OPTIONS"]),
    "t39b": lambda c, r: t39_rejected(c, r, ["INVITE", "OPTIONS"], tcp=True),
    "t39c_udp": lambda c, r: t39_rejected(c, r, ["INVITE"]),
    "t39c_tcp": lambda c, r: t39_rejected(c, r, ["INVITE"], tcp=True),
    "t39c_rel": lambda c, r: relayed(c, r, "sip:late@203.0.113.10;user=phone"),
    "t39d1": lambda c, r: relayed(c, r, "sip:late@192.168.1.19;user=phone;cause=302"),
    "t39d2": lambda c, r: relayed(c, r, "sip:late@192.168.1.19;transport=tcp"),
    "t39d3": lambda c, r: relayed(c, r, "sip:late@192.168.1.19;transport=xyz"),
    "t39d3_404": lambda c, r: rejected(c, r, ["INVITE"], "404"),
    "t39e": lambda c, r: rejected(c, r, ["OPTIONS"], "482"),
    "bed_ruri": bed_ruri,
}


def main():
    case, d = sys.argv[1], sys.argv[2]
    fn = CHECKS.get(case)
    if fn is None:
        print(f"NOCHECK {case}")
        return 2
    results = []
    try:
        fn(Case(d), results)
    except Exception as e:
        results.append(("checker error", False, repr(e)))
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {name} {detail if detail not in ('', None) else ''}".rstrip())
    return 0 if results and all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
