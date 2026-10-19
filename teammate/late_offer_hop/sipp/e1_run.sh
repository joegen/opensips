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

echo "fork $(git -C "$fork" rev-parse HEAD)" | tee -a "$summary"
cd "$here" || exit 1

docker rm -f rtpengine-lo > /dev/null 2>&1
t33=PASS
os="$(docker info --format '{{.OperatingSystem}}')"
echo "T-33 pre: docker OS '$os'" | tee -a "$summary"
case "$os" in *"Docker Desktop"*) t33=FAIL ;; esac
conf_src="$top/rtpengine/rtpengine.conf.sipp"
rtp_overlap() {
  local conf="$1" users="$2" lo hi u name range ulo uhi bad=""
  lo="$(sed -n 's/^port-min=//p' "$conf")"
  hi="$(sed -n 's/^port-max=//p' "$conf")"
  for u in $users; do
    name="${u%%:*}"; range="${u#*:}"; ulo="${range%-*}"; uhi="${range#*-}"
    if [ "$ulo" -le "$hi" ] && [ "$uhi" -ge "$lo" ]; then bad="$bad $name:$range"; fi
  done
  echo "RTPEngine range $lo-$hi; other RTP users: $users; overlapping:${bad:- none}"
  [ -z "$bad" ]
}
rtp_users="${LO_RTP_USERS:-sipp:6000-6100}"
if overlap_note="$(rtp_overlap "$conf_src" "$rtp_users")"; then :; else t33=FAIL; fi
echo "T-33 pre: $overlap_note" | tee -a "$summary"
busy="$(ss -lunH | awk '{split($4,a,":"); p=a[length(a)]; if (p >= 40000 && p <= 49999) print $4}' | tr '\n' ' ')"
echo "T-33 pre (recorded, not pass/fail, HD-LO-23): UDP sockets of other processes in the range: '${busy}'" | tee -a "$summary"
"$top/rtpengine/build_and_run_rtpengine.sh" "$conf_src" "$fork" > "$LO_RESULTS_DIR/container_build.log" 2>&1 || t33=FAIL
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
record T-33 "$t33" "AUTO pre/post-start checks"
[ -n "${LO_T33_ONLY:-}" ] && exit 0

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
  local case_name="$1" uac="$2" uas="$3" transport="${4:-udp}" expect_uas="${5:-0}"
  local out uac_rc uas_rc
  out="$(./run_case.sh "$case_name" "$uac" "$uas" "$transport" 2>&1 | tail -1)"
  uac_rc="$(sed -n 's/.*uac_rc=\([0-9]*\).*/\1/p' <<< "$out")"
  uas_rc="$(sed -n 's/.*uas_rc=\([0-9]*\).*/\1/p' <<< "$out")"
  LAST_DIR="$(latest "$case_name")"
  LAST_VERDICT=PASS
  LAST_NOTE="uac_rc=$uac_rc uas_rc=$uas_rc"
  [ "$uac_rc" = 0 ] && [ "$uas_rc" = "$expect_uas" ] || LAST_VERDICT=FAIL
  if python3 -I "$here/row_checks.py" "$case_name" "$LAST_DIR" > "$LAST_DIR/row_checks.txt" 2>&1; then
    LAST_METHOD=AUTO
  elif grep -q '^NOCHECK' "$LAST_DIR/row_checks.txt"; then
    LAST_METHOD=SCENARIO
  else
    LAST_METHOD=AUTO
    LAST_VERDICT=FAIL
  fi
  CASE_VERDICT[$case_name]="$LAST_VERDICT"
}

row() {
  record "$1" "$LAST_VERDICT" "$LAST_METHOD $2 $LAST_NOTE $LAST_DIR"
}

derived() {
  local row_id="$1" what="$2" verdict=PASS c
  shift 2
  for c in "$@"; do
    [ "${CASE_VERDICT[$c]:-FAIL}" = PASS ] || verdict=FAIL
    grep -q "^PASS $what" "$(latest "$c")/row_checks.txt" || verdict=FAIL
  done
  record "$row_id" "$verdict" "DERIVED '$what' on the artifacts of: $*"
}

declare -A CASE_VERDICT

case_run t01udp uac_late_offer.xml uas_answer.xml udp; row T-01 "udp"
case_run t01tcp uac_late_offer.xml uas_answer.xml tcp; row T-01 "tcp"
case_run t02a t02a_uac.xml uas_answer.xml; row T-02 "(a)"
case_run t02b t02b_uac.xml uas_answer.xml; row T-02 "(b)"
LO_CALLS=2 LO_UAC_ARGS="-l 1" case_run t03seq uac_late_offer.xml uas_answer.xml; row T-03 "in a row"
LO_CALLS=2 LO_UAC_ARGS="-r 20 -rp 1000" case_run t03same uac_late_offer.xml uas_answer.xml; row T-03 "same second"
case_run t04a uac_late_offer.xml uas_answer.xml; row T-04 "BYE from UAC"
case_run t04b t04b_uac.xml t04b_uas.xml; row T-04 "BYE from UAS"
case_run t05 t05_uac.xml t05_uas.xml; row T-05 "OPTIONS"
case_run t06 uac_late_offer.xml uas_answer.xml; row T-06 "S3/S4 NG"
case_run t07 t07_uac.xml t07_uas.xml; row T-07 ""
case_run t07r t07r_uac.xml t07r_uas.xml; row T-07 "(r)"
case_run t09r1 t09r1_uac.xml t09r1_uas.xml; row T-09 "run 1"
case_run t09r2 t09r2_uac.xml t09r2_uas.xml; row T-09 "run 2"
case_run t10r1 t10r1_uac.xml t10r1_uas.xml; row T-10 "run 1"
case_run t10r2 t10r2_uac.xml t10r2_uas.xml; row T-10 "run 2"
derived T-08 "S7 ACK relayed with RTPEngine's body" t09r1 t09r2 t10r1 t10r2
case_run t11_488 t11_488_uac.xml t11_488_uas.xml; row T-11 "488"
case_run t11_491 t11_491_uac.xml t11_491_uas.xml; row T-11 "491"
case_run t11_retr t11_retr_uac.xml t11_retr_uas.xml; row T-11 "retransmission"
LO_STOP_RTPENGINE_AT=1 case_run t11_down t11_down_uac.xml t11_down_uas.xml; row T-11 "RTPEngine down"
LO_STOP_RTPENGINE_AT=3 case_run t11_downack t11_downack_uac.xml t11_downack_uas.xml; row T-11 "RTPEngine down before ACK"
case_run t12 t12_uac.xml t12_uas.xml; row T-12 ""
case_run t13a t13a_uac.xml t13a_uas.xml; row T-13 "(a)"
LO_UAS_ARGS="-timeout 6" case_run t13b t13b_uac.xml t13b_uas.xml udp 97; row T-13 "(b)"
case_run t14 t14_uac.xml t14_uas.xml; row T-14 ""
case_run t16cancel t16cancel_uac.xml t16cancel_uas.xml; row T-16 "CANCEL"
case_run t16_486 t16_486_uac.xml t16_486_uas.xml; row T-16 "486"
case_run t16_603 t16_603_uac.xml t16_603_uas.xml; row T-16 "603"
case_run t16to1 t16to1_uac.xml t16to1_uas.xml; row T-16 "timeout 1"
LO_UAC_TIMEOUT=200 case_run t16to2 t16to2_uac.xml t16to2_uas.xml; row T-16 "timeout 2"
case_run t17 t17_uac.xml t17_uas.xml; row T-17 ""
case_run t18 t18_uac.xml t18_uas.xml; row T-18 ""
derived T-19 "T-19 versions" t18
case_run t20_488u t20_488u_uac.xml t20_488u_uas.xml; row T-20 "488 UAC offer"
case_run t20_488s t20_488s_uac.xml t20_488s_uas.xml; row T-20 "488 UAS offer"
case_run t20cancel t20cancel_uac.xml t20cancel_uas.xml; row T-20 "CANCEL"
case_run t20g1 t20g1_uac.xml t20g1_uas.xml; row T-20 "glare 1"
case_run t20g2 t20g2_uac.xml t20g2_uas.xml; row T-20 "glare 2"
case_run t21a t21a_uac.xml t21_uas.xml; row T-21 "(a)"
case_run t21b t21b_uac.xml t21_uas.xml; row T-21 "(b)"
case_run t22a t22_uac.xml t22_uas.xml; row T-22 "(a) PBX-side leg"
case_run t22b t22b_uac.xml t22b_uas.xml; row T-22 "(b) Karoo-side leg"
case_run t23_401 t23_401_uac.xml t23_401_uas.xml; row T-23 "401"
case_run t23_422 t23_422_uac.xml t23_422_uas.xml; row T-23 "422"
LO_STOP_RTPENGINE_AT=1.2 case_run t24 t24_uac.xml t24_uas.xml; row T-24 ""
LO_STOP_RTPENGINE_AT=1.2 case_run t25 t25_uac.xml t25_uas.xml; row T-25 ""
LO_STOP_RTPENGINE_AT=1.2 case_run t26 t26_uac.xml t26_uas.xml; row T-26 ""
case_run t27 t27_uac.xml t27_uas.xml; row T-27 ""
case_run t28 t28_uac.xml t28_uas.xml; row T-28 ""
LO_STOP_RTPENGINE_AT=0 LO_UAS_ARGS="-timeout 25" case_run t29 t29_uac.xml t29_uas.xml udp 97; row T-29 "(a) RTPEngine down"
LO_BLOCK_HOP_TO_UAS=1 LO_UAS_ARGS="-timeout 25" case_run t29b t29_uac.xml t29_uas.xml udp 97; row T-29 "(b) send failure"
case_run t30 t30_uac.xml t30_uas.xml; row T-30 ""
case_run t31 t31_uac.xml t31_uas.xml; row T-31 ""
case_run t32 t32_uac.xml t32_uas.xml; row T-32 ""

rows_total="$(awk '$1 ~ /^T-/ {print $1}' "$summary" | sort -u | wc -l)"
rows_failed="$(awk '$1 ~ /^T-/ && $2 == "FAIL" {print $1}' "$summary" | sort -u | wc -l)"
echo "entries: pass=$pass fail=$fail; rows: $((rows_total - rows_failed)) of $rows_total pass" | tee -a "$summary"
