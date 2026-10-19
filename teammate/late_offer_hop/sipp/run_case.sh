#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <case-name> <uac.xml> <uas.xml> [udp|tcp]" >&2
  exit 2
}

[ "$#" -ge 3 ] || usage

case_name="$1"
uac_xml="$2"
uas_xml="$3"
transport="${4:-udp}"

here="$(cd "$(dirname "$0")" && pwd)"
hop_dir="$(cd "$here/../opensips" && pwd)"
opensips=/opt/opensips-4.0.2/sbin/opensips
sipp="${LO_SIPP:-/usr/local/bin/sipp_lo}"
deploy=/opt/late_offer_hop/opensips
media_ip=192.168.1.19
hop_port=5080
uas_port=5060
uac_sip_ip=127.0.0.2
results_root="${LO_RESULTS_DIR:-/tmp/late_offer_hop_results}"
pidfile="$results_root/opensips.pid"
block_rule=(OUTPUT -p udp -s "$media_ip" --sport "$hop_port" -d "$media_ip" --dport "$uas_port" -j DROP)
out="$results_root/$case_name-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"

case "$transport" in
  udp) sipp_t=u1; local_src="$hop_dir/late_offer_hop.local.cfg.sipp" ;;
  tcp) sipp_t=t1; local_src="$out/late_offer_hop.local.cfg.tcp"
       sed -e "s#\"sip:$media_ip:$uas_port\"#\"sip:$media_ip:$uas_port;transport=tcp\"#" \
         "$hop_dir/late_offer_hop.local.cfg.sipp" > "$local_src" ;;
  *) usage ;;
esac

cp "${LO_HOP_CFG:-$hop_dir/late_offer_hop.cfg}" "$deploy/late_offer_hop.cfg"
cp "$local_src" "$deploy/late_offer_hop.local.cfg"

stop_hop() {
  if [ -f "$pidfile" ]; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  fi
  pkill -f "$deploy/late_offer_hop.cfg" 2>/dev/null || true
  sleep 0.5
}

hop_port_busy() {
  [ -n "$(ss -lunH "sport = :$hop_port")$(ss -ltnH "sport = :$hop_port")" ]
}

rtpengine_running() {
  [ "$(docker inspect -f '{{.State.Running}}' rtpengine-lo 2>/dev/null)" = "true" ]
}

if ! rtpengine_running; then
  docker start rtpengine-lo > /dev/null
fi
python3 -I "$here/ng_ping.py" 127.0.0.1 22222 30 > /dev/null
if ! "$opensips" -c -f "$deploy/late_offer_hop.cfg" > "$out/opensips_check.log" 2>&1; then
  echo "uac_rc=98 uas_rc=98 out=$out"
  exit 1
fi
stop_hop
if hop_port_busy; then
  echo "port $hop_port is still in use before start" > "$out/runner_error.log"
  echo "uac_rc=99 uas_rc=99 out=$out"
  exit 1
fi

sudo -n tcpdump -i any -s 0 -U -w "$out/capture.pcap" \
  "udp port 22222 or port $hop_port or port $uas_port or udp portrange 6000-6100 or udp portrange 40000-49999" \
  > "$out/tcpdump.log" 2>&1 &
tcpdump_pid=$!
sleep 1

start_ts="$(date "+%Y-%m-%d %H:%M:%S")"
"$opensips" -F -f "$deploy/late_offer_hop.cfg" > "$out/opensips_stdout.log" 2>&1 &
echo $! > "$pidfile"
sleep 1
if ! kill -0 "$(cat "$pidfile")" 2>/dev/null || ! hop_port_busy; then
  echo "the hop did not start or does not own port $hop_port" > "$out/runner_error.log"
  sudo -n kill "$tcpdump_pid" 2>/dev/null || true
  echo "uac_rc=99 uas_rc=99 out=$out"
  exit 1
fi

uas_timeout=()
case " ${LO_UAS_ARGS:-} " in
  *" -timeout "*) ;;
  *) uas_timeout=(-timeout "$(( ${LO_UAC_TIMEOUT:-60} + 15 ))") ;;
esac

"$sipp" -sf "$uas_xml" -i "$media_ip" -p "$uas_port" -mi "$media_ip" -mp 6000 \
  -t "$sipp_t" -m "${LO_CALLS:-1}" ${LO_UAS_ARGS:-} "${uas_timeout[@]}" -trace_msg -message_file "$out/uas_messages.log" \
  -trace_err -error_file "$out/uas_errors.log" -trace_logs -log_file "$out/uas_logs.log" -nostdin > "$out/uas_stdout.log" 2>&1 &
uas_pid=$!
sleep 0.5

if [ -n "${LO_STOP_RTPENGINE_AT:-}" ]; then
  (sleep "$LO_STOP_RTPENGINE_AT"; docker stop -t 0 rtpengine-lo > /dev/null; date +%s.%N > "$out/rtpengine_stopped_at") &
fi
if [ -n "${LO_BLOCK_HOP_TO_UAS:-}" ]; then
  sudo -n iptables -I "${block_rule[@]}"
fi
set +e
"$sipp" -sf "$uac_xml" "$media_ip:$hop_port" -i "$uac_sip_ip" -p 5070 -mi "$media_ip" -mp 6050 \
  -t "$sipp_t" -s late -m "${LO_CALLS:-1}" ${LO_UAC_ARGS:-} -timeout "${LO_UAC_TIMEOUT:-60}" -trace_msg -message_file "$out/uac_messages.log" \
  -trace_err -error_file "$out/uac_errors.log" -trace_logs -log_file "$out/uac_logs.log" -nostdin > "$out/uac_stdout.log" 2>&1
uac_rc=$?
if [ -n "${LO_BLOCK_HOP_TO_UAS:-}" ]; then
  sudo -n iptables -D "${block_rule[@]}"
fi
wait "$uas_pid"
uas_rc=$?
set -e

sleep 1
stop_hop
sudo -n kill "$tcpdump_pid" 2>/dev/null || true
sudo -n journalctl --no-pager -q --since "$start_ts" _COMM=opensips > "$out/opensips.log" 2>&1 || true
wait "$tcpdump_pid" 2>/dev/null || true

if ! rtpengine_running; then
  docker start rtpengine-lo > /dev/null
  python3 -I "$here/ng_ping.py" 127.0.0.1 22222 30 > /dev/null
fi
echo "uac_rc=$uac_rc uas_rc=$uas_rc out=$out"
[ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ]
