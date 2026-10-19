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
deploy=/opt/late_offer_hop/opensips
media_ip=192.168.1.19
hop_port=5080
uas_port=5060
uac_sip_ip=127.0.0.2
results_root="${LO_RESULTS_DIR:-/tmp/late_offer_hop_results}"
out="$results_root/$case_name-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"

case "$transport" in
  udp) sipp_t=u1; local_src="$hop_dir/late_offer_hop.local.cfg.sipp" ;;
  tcp) sipp_t=t1; local_src="$out/late_offer_hop.local.cfg.tcp"
       sed -e 's#"sip:192.168.1.19:5060"#"sip:192.168.1.19:5060;transport=tcp"#' \
         "$hop_dir/late_offer_hop.local.cfg.sipp" > "$local_src" ;;
  *) usage ;;
esac

cp "$hop_dir/late_offer_hop.cfg" "$deploy/late_offer_hop.cfg"
cp "$local_src" "$deploy/late_offer_hop.local.cfg"

stop_hop() {
  if [ -f "$out/../opensips.pid" ]; then
    kill "$(cat "$out/../opensips.pid")" 2>/dev/null || true
    rm -f "$out/../opensips.pid"
  fi
  pkill -f "$opensips -f $deploy/late_offer_hop.cfg" 2>/dev/null || true
  sleep 0.5
}

python3 -I "$here/ng_ping.py" 127.0.0.1 22222 30 > /dev/null
"$opensips" -c -f "$deploy/late_offer_hop.cfg" > "$out/opensips_check.log" 2>&1
stop_hop

sudo -n tcpdump -i any -s 0 -U -w "$out/capture.pcap" \
  "udp port 22222 or port $hop_port or port $uas_port or udp portrange 6000-6100 or udp portrange 40000-49999" \
  > "$out/tcpdump.log" 2>&1 &
tcpdump_pid=$!
sleep 1

start_ts="$(date "+%Y-%m-%d %H:%M:%S")"
"$opensips" -F -f "$deploy/late_offer_hop.cfg" > "$out/opensips_stdout.log" 2>&1 &
echo $! > "$out/../opensips.pid"
sleep 1

sipp -sf "$uas_xml" -i "$media_ip" -p "$uas_port" -mi "$media_ip" -mp 6000 \
  -t "$sipp_t" -m 1 -trace_msg -message_file "$out/uas_messages.log" \
  -trace_err -error_file "$out/uas_errors.log" -trace_logs -log_file "$out/uas_logs.log" -nostdin > "$out/uas_stdout.log" 2>&1 &
uas_pid=$!
sleep 0.5

set +e
sipp -sf "$uac_xml" "$media_ip:$hop_port" -i "$uac_sip_ip" -p 5070 -mi "$media_ip" -mp 6050 \
  -t "$sipp_t" -s late -m 1 -timeout 60 -trace_msg -message_file "$out/uac_messages.log" \
  -trace_err -error_file "$out/uac_errors.log" -trace_logs -log_file "$out/uac_logs.log" -nostdin > "$out/uac_stdout.log" 2>&1
uac_rc=$?
wait "$uas_pid"
uas_rc=$?
set -e

sleep 1
stop_hop
sudo -n kill "$tcpdump_pid" 2>/dev/null || true
sudo -n journalctl --no-pager -q --since "$start_ts" -t opensips > "$out/opensips.log" 2>&1 || true
wait "$tcpdump_pid" 2>/dev/null || true

echo "uac_rc=$uac_rc uas_rc=$uas_rc out=$out"
[ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ]
