#!/usr/bin/env bash
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
top="$(cd "$here/.." && pwd)"
fork="${1:-/workspace/rtpengine}"
export LO_RESULTS_DIR="${LO_RESULTS_DIR:-/tmp/late_offer_hop_results/e1-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LO_RESULTS_DIR"
summary="$LO_RESULTS_DIR/summary.txt"
: > "$summary"
pass=0
fail=0

record() {
  echo "$1 $2 $3" | tee -a "$summary"
  if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}

latest() {
  ls -d "$LO_RESULTS_DIR/$1"-* | tail -1
}

ng_count() {
  local dir="$1"
  local cid
  cid="$(grep -m1 -i '^Call-ID:' "$dir/uac_messages.log" | awk '{print $2}' | tr -d '\r')"
  python3 -I "$here/ng_log.py" "$dir/capture.pcap" "$cid" | grep -vc -- '->'
}

echo "fork $(git -C "$fork" rev-parse HEAD)" | tee -a "$summary"
cd "$here" || exit 1

docker rm -f rtpengine-lo > /dev/null 2>&1
t33=PASS
os="$(docker info --format '{{.OperatingSystem}}')"
echo "T-33 pre: docker OS '$os'" | tee -a "$summary"
case "$os" in *"Docker Desktop"*) t33=FAIL ;; esac
busy="$(ss -lunH | awk '{split($4,a,":"); p=a[length(a)]; if (p >= 40000 && p <= 49999) print $4}')"
echo "T-33 pre: UDP listeners in 40000-49999: '${busy}'" | tee -a "$summary"
[ -z "$busy" ] || t33=FAIL
"$top/rtpengine/build_and_run_rtpengine.sh" "$top/rtpengine/rtpengine.conf.sipp" "$fork" > "$LO_RESULTS_DIR/container_build.log" 2>&1 || t33=FAIL
python3 -I "$here/ng_ping.py" 127.0.0.1 22222 30 > /dev/null || t33=FAIL
ng="$(sudo -n ss -lunpH | grep rtpengine | awk '{print $4}' | sort -u | tr '\n' ' ')"
echo "T-33 post: rtpengine UDP sockets bound before calls: '$ng'" | tee -a "$summary"
[ "$ng" = "127.0.0.1:22222 " ] || t33=FAIL
tcp="$(sudo -n ss -ltnpH | grep -c rtpengine)"
echo "T-33 post: rtpengine TCP listeners: $tcp" | tee -a "$summary"
[ "$tcp" = 0 ] || t33=FAIL
netmode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' rtpengine-lo)"
echo "T-33 post: network mode '$netmode'" | tee -a "$summary"
[ "$netmode" = host ] || t33=FAIL
grep -qx 'table=-1' /opt/late_offer_hop/rtpengine/rtpengine.conf && grep -qx 'port-min=40000' /opt/late_offer_hop/rtpengine/rtpengine.conf \
  && grep -qx 'port-max=49999' /opt/late_offer_hop/rtpengine/rtpengine.conf || t33=FAIL
record T-33 "$t33" "pre/post-start checks"

lab_tmp="$LO_RESULTS_DIR/lab_check"
mkdir -p "$lab_tmp"
sed -e 's/<proto>/udp/g; s/<HOP_IP>/192.168.1.19/; s/<HOP_PORT>/5080/; s/<KAROO_IP>/192.168.1.19/' \
  "$top/opensips/late_offer_hop.local.cfg.lab" > /opt/late_offer_hop/opensips/late_offer_hop.local.cfg
if /opt/opensips-4.0.2/sbin/opensips -c -f "$top/opensips/late_offer_hop.cfg" > "$lab_tmp/check.log" 2>&1; then
  record cfg-lab PASS "'opensips -c' with the placeholder-filled .lab file"
else
  record cfg-lab FAIL "'opensips -c' with the placeholder-filled .lab file"
fi

case_run() {
  local row="$1" case_name="$2" uac="$3" uas="$4" transport="${5:-udp}" expect_uas="${6:-0}"
  local out rc_line uac_rc uas_rc dir verdict note
  out="$(./run_case.sh "$case_name" "$uac" "$uas" "$transport" 2>&1 | tail -1)"
  uac_rc="$(sed -n 's/.*uac_rc=\([0-9]*\).*/\1/p' <<< "$out")"
  uas_rc="$(sed -n 's/.*uas_rc=\([0-9]*\).*/\1/p' <<< "$out")"
  dir="$(latest "$case_name")"
  verdict=PASS
  note="uac_rc=$uac_rc uas_rc=$uas_rc"
  [ "$uac_rc" = 0 ] || verdict=FAIL
  [ "$uas_rc" = "$expect_uas" ] || verdict=FAIL
  LAST_DIR="$dir"
  LAST_VERDICT="$verdict"
  LAST_NOTE="$note"
}

check_t01() {
  python3 -I "$here/check_t01.py" "$LAST_DIR" > "$LAST_DIR/check_t01.txt" 2>&1 || LAST_VERDICT=FAIL
  LAST_NOTE="$LAST_NOTE t01checks=$(grep -c PASS "$LAST_DIR/check_t01.txt")/$(grep -cE 'PASS|FAIL' "$LAST_DIR/check_t01.txt")"
}

zero_ng() {
  local n
  n="$(ng_count "$LAST_DIR")"
  LAST_NOTE="$LAST_NOTE ng=$n"
  [ "$n" = 0 ] || LAST_VERDICT=FAIL
}

nothing_at_uas() {
  local n
  n="$(grep -c 'message received' "$LAST_DIR/uas_messages.log" 2>/dev/null)"
  LAST_NOTE="$LAST_NOTE uas_received=${n:-0}"
  [ "${n:-0}" = 0 ] || LAST_VERDICT=FAIL
}

row() {
  record "$1" "$LAST_VERDICT" "$2 $LAST_NOTE $LAST_DIR"
}

case_run T-01 t01udp uac_late_offer.xml uas_answer.xml udp; check_t01; row T-01 "udp"
case_run T-01 t01tcp uac_late_offer.xml uas_answer.xml tcp; check_t01; row T-01 "tcp"
case_run T-02 t02a t02a_uac.xml uas_answer.xml; check_t01; row T-02 "(a)"
case_run T-02 t02b t02b_uac.xml uas_answer.xml; check_t01; row T-02 "(b)"
LO_CALLS=2 LO_UAC_ARGS="-l 1" case_run T-03 t03seq uac_late_offer.xml uas_answer.xml; row T-03 "in a row"
LO_CALLS=2 LO_UAC_ARGS="-r 20 -rp 1000" case_run T-03 t03same uac_late_offer.xml uas_answer.xml; row T-03 "same second"
case_run T-04 t04a uac_late_offer.xml uas_answer.xml; row T-04 "BYE from UAC"
case_run T-04 t04b t04b_uac.xml t04b_uas.xml; row T-04 "BYE from UAS"
case_run T-05 t05 t05_uac.xml t05_uas.xml; zero_ng; row T-05 "OPTIONS"
case_run T-06 t06 uac_late_offer.xml uas_answer.xml; row T-06 "S3/S4 NG"
case_run T-07 t07 t07_uac.xml t07_uas.xml; row T-07 ""
case_run T-07 t07r t07r_uac.xml t07r_uas.xml; row T-07 "(r)"
case_run T-09 t09r1 t09r1_uac.xml t09r1_uas.xml; row T-09 "run 1"
case_run T-09 t09r2 t09r2_uac.xml t09r2_uas.xml; row T-09 "run 2"
case_run T-10 t10r1 t10r1_uac.xml t10r1_uas.xml; row T-10 "run 1"
case_run T-10 t10r2 t10r2_uac.xml t10r2_uas.xml; row T-10 "run 2"
LAST_VERDICT=PASS; for r in T-09 T-10; do grep -q "^$r FAIL" "$summary" && LAST_VERDICT=FAIL; done
record T-08 "$LAST_VERDICT" "shown by the T-09 and T-10 traces (S7 on the CSeq 2 downstream ACK and the upstream ACK)"
case_run T-11 t11_488 t11_488_uac.xml t11_488_uas.xml; row T-11 "488"
case_run T-11 t11_491 t11_491_uac.xml t11_491_uas.xml; row T-11 "491"
case_run T-11 t11_retr t11_retr_uac.xml t11_retr_uas.xml; row T-11 "retransmission"
LO_STOP_RTPENGINE_AT=1 case_run T-11 t11_down t11_down_uac.xml t11_down_uas.xml; row T-11 "RTPEngine down"
LO_STOP_RTPENGINE_AT=3 case_run T-11 t11_downack t11_downack_uac.xml t11_downack_uas.xml; row T-11 "RTPEngine down before ACK"
case_run T-12 t12 t12_uac.xml t12_uas.xml; row T-12 ""
case_run T-13 t13a t13a_uac.xml t13a_uas.xml; row T-13 "(a)"
LO_UAS_ARGS="-timeout 6" case_run T-13 t13b t13b_uac.xml t13b_uas.xml udp 97; zero_ng; nothing_at_uas; row T-13 "(b)"
case_run T-14 t14 t14_uac.xml t14_uas.xml; row T-14 ""
case_run T-16 t16cancel t16cancel_uac.xml t16cancel_uas.xml; row T-16 "CANCEL"
case_run T-16 t16_486 t16_486_uac.xml t16_486_uas.xml; row T-16 "486"
case_run T-16 t16_603 t16_603_uac.xml t16_603_uas.xml; row T-16 "603"
case_run T-16 t16to1 t16to1_uac.xml t16to1_uas.xml; row T-16 "timeout 1"
LO_UAC_TIMEOUT=200 case_run T-16 t16to2 t16to2_uac.xml t16to2_uas.xml; row T-16 "timeout 2"
case_run T-17 t17 t17_uac.xml t17_uas.xml; row T-17 ""
case_run T-18 t18 t18_uac.xml t18_uas.xml; row T-18 "and T-19"
record T-19 "$LAST_VERDICT" "same run as T-18 $LAST_DIR"
case_run T-20 t20_488u t20_488u_uac.xml t20_488u_uas.xml; row T-20 "488 UAC offer"
case_run T-20 t20_488s t20_488s_uac.xml t20_488s_uas.xml; row T-20 "488 UAS offer"
case_run T-20 t20cancel t20cancel_uac.xml t20cancel_uas.xml; row T-20 "CANCEL"
case_run T-20 t20g1 t20g1_uac.xml t20g1_uas.xml; row T-20 "glare 1"
case_run T-20 t20g2 t20g2_uac.xml t20g2_uas.xml; row T-20 "glare 2"
for c in t21a t21b; do
  case_run T-21 "$c" "${c}_uac.xml" t21_uas.xml
  python3 -I "$here/rtp_pts.py" "$LAST_DIR/capture.pcap" > "$LAST_DIR/rtp_pts.txt"
  toward_uas="$(awk '$3 ~ /:6000$/ && $4 != "pt=" && $4 != "pt=0" {print $4 $5}' "$LAST_DIR/rtp_pts.txt" | tr '\n' ' ')"
  LAST_NOTE="$LAST_NOTE toward_uas_events='$toward_uas'"
  if [ "$c" = t21a ]; then [ -z "$toward_uas" ] || LAST_VERDICT=FAIL; else [ "$toward_uas" = "pt=101packets=10 " ] || LAST_VERDICT=FAIL; fi
  row T-21 "$c"
done
case_run T-22 t22 t22_uac.xml t22_uas.xml; row T-22 ""
case_run T-23 t23_401 t23_401_uac.xml t23_401_uas.xml; row T-23 "401"
case_run T-23 t23_422 t23_422_uac.xml t23_422_uas.xml; row T-23 "422"
LO_STOP_RTPENGINE_AT=1.2 case_run T-24 t24 t24_uac.xml t24_uas.xml; row T-24 ""
LO_STOP_RTPENGINE_AT=1.2 case_run T-25 t25 t25_uac.xml t25_uas.xml; row T-25 ""
LO_STOP_RTPENGINE_AT=1.2 case_run T-26 t26 t26_uac.xml t26_uas.xml; row T-26 ""
case_run T-27 t27 t27_uac.xml t27_uas.xml; zero_ng; row T-27 ""
case_run T-28 t28 t28_uac.xml t28_uas.xml; zero_ng; row T-28 ""
LO_STOP_RTPENGINE_AT=0 LO_UAS_ARGS="-timeout 25" case_run T-29 t29 t29_uac.xml t29_uas.xml udp 97; nothing_at_uas; row T-29 ""
case_run T-30 t30 t30_uac.xml t30_uas.xml; row T-30 ""
case_run T-31 t31 t31_uac.xml t31_uas.xml; row T-31 ""
case_run T-32 t32 t32_uac.xml t32_uas.xml; row T-32 ""

echo "cases: pass=$pass fail=$fail" | tee -a "$summary"
