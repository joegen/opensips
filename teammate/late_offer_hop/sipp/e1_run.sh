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

fork_head="$(git -C "$fork" rev-parse --verify HEAD)" || fork_head=""
echo "fork ${fork_head:-<git rev-parse failed>}" | tee -a "$summary"
echo "sipp $(${LO_SIPP:-/usr/local/bin/sipp_lo} -v 2>&1 | grep -m1 -o 'SIPp v[^ ]*')" | tee -a "$summary"
[ -n "$fork_head" ] || record fork-commit FAIL "git -C $fork rev-parse --verify HEAD failed (C5.publishing step 4 needs the fork commit)"
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
rtpe_id="$(docker inspect -f '{{.Image}}' rtpengine-lo)"
echo "rtpengine-lo image $rtpe_id (fork $fork_head)" | tee -a "$summary"
export LO_RTPENGINE_IMAGE_ID="$rtpe_id"
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
priv_check() {
  local c="$1" opts uid rc_a rc_c
  opts="$(docker inspect -f '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' "$c" 2>&1)"
  grep -Eqx 'no-new-privileges([:=]true)?' <<< "$opts"; rc_a=$?
  uid="$(docker exec "$c" id -u 2>&1)"
  docker exec "$c" sudo -n true > /dev/null 2>&1; rc_c=$?
  echo "SecurityOpt='$(tr '\n' ' ' <<< "$opts")' (a)=$rc_a; id -u='$uid'; sudo -n true exit $rc_c"
  PRIV_A=$rc_a PRIV_UID=$uid PRIV_C=$rc_c
}
priv_check rtpengine-lo > "$LO_RESULTS_DIR/t33_priv.txt"
echo "T-33 post: privilege check on rtpengine-lo: $(cat "$LO_RESULTS_DIR/t33_priv.txt")" | tee -a "$summary"
[ "$PRIV_A" = 0 ] && [ "$PRIV_UID" = 1000 ] && [ "$PRIV_C" != 0 ] || t33=FAIL
docker rm -f rtpengine-lo-nnp-ctl > /dev/null 2>&1
docker run -d --name rtpengine-lo-nnp-ctl --network none --entrypoint sleep "$rtpe_id" 120 > /dev/null
priv_check rtpengine-lo-nnp-ctl > "$LO_RESULTS_DIR/t33_priv_control.txt"
docker rm -f rtpengine-lo-nnp-ctl > /dev/null 2>&1
echo "T-33 control: same check on rtpengine-lo-nnp-ctl (no option): $(cat "$LO_RESULTS_DIR/t33_priv_control.txt")" | tee -a "$summary"
[ "$PRIV_A" != 0 ] && [ "$PRIV_UID" = 1000 ] && [ "$PRIV_C" = 0 ] || t33=FAIL
grep -qx 'table=-1' /opt/late_offer_hop/rtpengine/rtpengine.conf && grep -qx 'port-min=40000' /opt/late_offer_hop/rtpengine/rtpengine.conf \
  && grep -qx 'port-max=49999' /opt/late_offer_hop/rtpengine/rtpengine.conf || t33=FAIL
record T-33 "$t33" "AUTO pre/post-start checks"
if [ -n "${LO_T33_ONLY:-}" ]; then [ "$fail" = 0 ]; exit $?; fi

lab_tmp="$LO_RESULTS_DIR/lab_check"
mkdir -p "$lab_tmp"

fill_lab() {
  sed -e "s/<KAROO_PRIVATE_IP>/$2/g; s/<KAROO_PUBLIC_IP>/$3/g; s/<HOP_PORT>/$4/g; s/<NG_PORT>/$5/g" \
    "$top/opensips/late_offer_hop.local.cfg.lab" > "$1"
}

lab_cfg_check() {
  local copy="$1" log="$2"
  if [ -n "${LO_HOP_IMAGE:-}" ]; then
    docker run --rm --network host -v "$copy:/opt/late_offer_hop/opensips/late_offer_hop.local.cfg:ro" \
      "$LO_HOP_IMAGE" -c > "$log" 2>&1
  else
    cp "$copy" /opt/late_offer_hop/opensips/late_offer_hop.local.cfg
    /opt/opensips-4.0.2/sbin/opensips -c -f "$top/opensips/late_offer_hop.cfg" > "$log" 2>&1
  fi
}

lab_check() {
  local name="$1" priv="$2" pub="$3" port="$4" ng="$5" copy note
  copy="$lab_tmp/$name.local.cfg"
  note="filled with $priv/$pub/$port/$ng"
  fill_lab "$copy" "$priv" "$pub" "$port" "$ng"
  if grep -qE '<(KAROO_PRIVATE_IP|KAROO_PUBLIC_IP|HOP_PORT|NG_PORT)>' "$copy"; then
    record "$name" FAIL "placeholder left in the filled .lab copy ($note)"
    return
  fi
  if ! lab_cfg_check "$copy" "$lab_tmp/$name.check.log"; then
    if ! grep -q 'failed to initialize list addresses' "$lab_tmp/$name.check.log"; then
      record "$name" FAIL "'-c' failed for a reason other than a socket address ($note; log $lab_tmp/$name.check.log)"
      return
    fi
    copy="$lab_tmp/$name.bed.local.cfg"
    note="$note; first '-c' refused a socket address (log $lab_tmp/$name.check.log), so bed address 192.168.1.19 is used in place of $priv, alias kept"
    fill_lab "$copy" 192.168.1.19 "$pub" "$port" "$ng"
    if ! lab_cfg_check "$copy" "$lab_tmp/$name.bed.check.log"; then
      record "$name" FAIL "'-c' with the filled .lab copy ($note)"
      return
    fi
  fi
  record "$name" PASS "'-c' with the filled .lab copy ($note)"
}

lab_check cfg-lab-pair1 10.2.0.15 4.155.11.192 6060 22222
lab_check cfg-lab-pair2 10.2.0.16 4.155.41.131 6060 22223

if [ -n "${LO_HOP_IMAGE:-}" ]; then
  : "${LO_HOP_BUILD_COMMIT:?image mode needs LO_HOP_BUILD_COMMIT, the commit the hop image was built from}"
  t35=PASS
  "$here/t35_hop_image.sh" "$LO_HOP_IMAGE" "$LO_HOP_BUILD_COMMIT" "$LO_RESULTS_DIR/t35" > /dev/null || t35=FAIL
  "$here/t35_rtpengine_image.sh" "$fork" "$rtpe_id" "$LO_RESULTS_DIR/t35" > /dev/null || t35=FAIL
  record T-35 "$t35" "AUTO hop image $(docker image inspect -f '{{.Id}}' "$LO_HOP_IMAGE") build $LO_HOP_BUILD_COMMIT; rtpengine image $rtpe_id; items in $LO_RESULTS_DIR/t35; .lab part = cfg-lab-pair1/2"
  out="$(LO_LOCAL_UNREADABLE=1 ./run_case.sh image-start-unreadable uac_late_offer.xml uas_answer.xml 2>&1 | tail -1)"
  if grep -q 'uac_rc=99' <<< "$out" && grep -q 'did not start' "$(latest image-start-unreadable)/runner_error.log" \
    && grep -q 'Permission denied' "$(latest image-start-unreadable)/opensips_stdout.log"; then
    record image-start-unreadable PASS "a case started with an unreadable local file FAILS at the start check, hop log 'Permission denied' ($out)"
  else
    record image-start-unreadable FAIL "a case started with an unreadable local file did not FAIL at the start check with 'Permission denied' in the hop log ($out)"
  fi
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

uac_default="$(sed -n 's/^uac_sip_ip="${LO_UAC_SIP_IP:-\(.*\)}"$/\1/p' run_case.sh)"
uac_ip="${LO_UAC_SIP_IP:-$uac_default}"
karoo_private="$(sed -n 's/.*lo_karoo_private_ip) = "\(.*\)";/\1/p' "$top/opensips/late_offer_hop.local.cfg.sipp")"
karoo_public="$(sed -n 's/.*lo_karoo_public_ip) = "\(.*\)";/\1/p' "$top/opensips/late_offer_hop.local.cfg.sipp")"
if [ -n "$uac_ip" ] && [ -n "$karoo_private" ] && [ -n "$karoo_public" ] && [ "$uac_ip" != "$karoo_private" ] && [ "$uac_ip" != "$karoo_public" ]; then
  record t38-precondition PASS "UAC -i $uac_ip differs from lo_karoo_private_ip $karoo_private and lo_karoo_public_ip $karoo_public"
else
  record t38-precondition FAIL "UAC -i '$uac_ip', lo_karoo_private_ip '$karoo_private', lo_karoo_public_ip '$karoo_public'"
  echo "stopped before the first case: t38-precondition FAIL" | tee -a "$summary"
  exit 1
fi
case_run t01udp uac_late_offer.xml uas_answer.xml udp; row T-01 "udp"
case_run t01tcp uac_late_offer.xml uas_answer.xml tcp; row T-01 "tcp"
for c in t01udp t01tcp; do
  if python3 -I "$here/row_checks.py" bed_ruri "$(latest "$c")" > "$LO_RESULTS_DIR/bed-ruri-$c.txt" 2>&1; then
    record "bed-ruri-$c" PASS "the $c INVITE names the UAS 192.168.1.19:5060 and is sent to the hop 192.168.1.19:5080"
  else
    record "bed-ruri-$c" FAIL "bed Request-URI rule not in force for $c (see bed-ruri-$c.txt)"
  fi
done
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

LO_UAC_SIP_IP="$karoo_private" LO_UAS_ARGS="-timeout 6" case_run t38priv t38_uac.xml t13b_uas.xml udp 97; row T-38 "UDP from lo_karoo_private_ip"
LO_UAC_SIP_IP="$karoo_public" LO_UAS_ARGS="-timeout 6" case_run t38pub t38_uac.xml t13b_uas.xml udp 97; row T-38 "UDP from lo_karoo_public_ip"
LO_UAC_SIP_IP="$karoo_private" LO_UAS_ARGS="-timeout 6" case_run t38tcp t38tcp_uac.xml t13b_uas.xml tcp 97; row T-38 "TCP from lo_karoo_private_ip"

negative_control() {
  local name="$1" check="$2" dir="$3" out="$LO_RESULTS_DIR/$1.txt" f
  shift 3
  if python3 -I "$here/row_checks.py" "$check" "$dir" > "$out" 2>&1; then
    record "$name" FAIL "the $check check PASSED on $dir"
    return
  fi
  for f in "$@"; do
    if ! grep '^FAIL ' "$out" | grep -qF -- "$f"; then
      record "$name" FAIL "the $check check FAILS on $dir, but not on '$f'"
      return
    fi
  done
  record "$name" PASS "the $check check FAILS on $dir, as required${*:+ (failing: $*)}"
}
negative_control t38-negative-control t38priv "$(latest t01udp)"

hop_remote="192.168.1.19:5080"
alias_ip=203.0.113.10
alias_remote="$alias_ip:5080"
LO_UAC_REMOTE="$hop_remote" LO_UAS_ARGS="-timeout 6" case_run t39a t39_uac.xml t13b_uas.xml udp 97; row T-39 "(a) UDP INVITE and OPTIONS naming the hop"
LO_UAC_REMOTE="$hop_remote" LO_UAS_ARGS="-timeout 6" case_run t39b t39_uac.xml t13b_uas.xml tcp 97; row T-39 "(b) TCP INVITE and OPTIONS naming the hop"
LO_LOCAL_ALIAS="$alias_ip" LO_UAC_REMOTE="$alias_remote" LO_UAS_ARGS="-timeout 6" case_run t39c_udp t39inv_uac.xml t13b_uas.xml udp 97; row T-39 "(c) UDP INVITE naming the alias"
LO_LOCAL_ALIAS="$alias_ip" LO_UAC_REMOTE="$alias_remote" LO_UAS_ARGS="-timeout 6" case_run t39c_tcp t39inv_uac.xml t13b_uas.xml tcp 97; row T-39 "(c) TCP INVITE naming the alias"
LO_LOCAL_ALIAS="$alias_ip" LO_UAC_ARGS="-key ruri sip:late@$alias_ip;user=phone" case_run t39c_rel t39lit_uac.xml uas_answer.xml udp; row T-39 "(c) alias host without port relayed"
LO_UAC_ARGS="-key ruri sip:late@192.168.1.19;user=phone;cause=302" case_run t39d1 t39lit_uac.xml uas_answer.xml udp; row T-39 "(d1) relayed"
LO_UAC_ARGS="-key ruri sip:late@192.168.1.19;transport=tcp" case_run t39d2 t39lit_uac.xml uas_answer.xml udp; row T-39 "(d2) relayed"
LO_UAC_ARGS="-key ruri sip:late@192.168.1.19;transport=xyz" case_run t39d3 t39lit_uac.xml uas_answer.xml udp; row T-39 "(d3) relayed"
LO_UAC_REMOTE="$hop_remote" LO_UAC_SIP_IP="$karoo_private" LO_UAS_ARGS="-timeout 6" case_run t39e t39e_uac.xml t13b_uas.xml udp 97; row T-39 "(e) 482 before 404"
negative_control t39-negative-control t39a "$(latest t01udp)" "capture holds the INVITE to the hop and the hop's 404" "no request with the row's Call-IDs reaches the UAS" "no NG command"
negative_control t39-relayed-negative-control t39a_relayed "$(latest t39a)" "the UAS receives exactly that Request-URI" "an NG offer is seen" "the hop log holds no 'naming the hop' line"
noguard="$LO_RESULTS_DIR/late_offer_hop.noguard.cfg"
sed 's/if (\$rp != 0 \&\& is_myself(\$rd, \$rp)) {/if (is_myself($rd, $rp)) {/' "$top/opensips/late_offer_hop.cfg" > "$noguard"
if [ "$(diff "$top/opensips/late_offer_hop.cfg" "$noguard" | grep -c '^[<>]')" = 2 ]; then
  LO_HOP_IMAGE="" LO_HOP_CFG="$noguard" LO_UAC_ARGS="-key ruri sip:late@192.168.1.19;transport=xyz" LO_UAS_ARGS="-timeout 6" LO_UAC_TIMEOUT=10 \
    ./run_case.sh t39d3-noguard t39lit_uac.xml t13b_uas.xml udp > /dev/null 2>&1
  ng_dir="$(latest t39d3-noguard)"
  if ! python3 -I "$here/row_checks.py" t39d3 "$ng_dir" > "$LO_RESULTS_DIR/t39-guard-control.txt" 2>&1 \
    && python3 -I "$here/row_checks.py" t39d3_404 "$ng_dir" >> "$LO_RESULTS_DIR/t39-guard-control.txt" 2>&1; then
    record t39-guard-control PASS "(d3) against the logic file without '\$rp != 0 && ' gets 404 and the relayed check FAILS ($ng_dir)"
  else
    record t39-guard-control FAIL "(d3) without the guard did not get 404, or the relayed check passed ($ng_dir)"
  fi
else
  record t39-guard-control FAIL "the scratch logic file is not a one-line change of the guard"
fi

rtpe_restart() {
  "$top/rtpengine/build_and_run_rtpengine.sh" "$1" "$fork" > "$LO_RESULTS_DIR/container_build_$2.log" 2>&1 \
    && python3 -I "$here/ng_ping.py" 127.0.0.1 22222 30 > /dev/null \
    && [ "$(docker inspect -f '{{.Image}}' rtpengine-lo)" = "$rtpe_id" ]
}
t37_conf="$LO_RESULTS_DIR/rtpengine.conf.t37"
sed 's/^interface=192\.168\.1\.19$/interface=192.168.1.19!203.0.113.10/' "$conf_src" > "$t37_conf"
if [ "$(diff "$conf_src" "$t37_conf" | grep -c '^[<>]')" = 2 ] && grep -qx 'interface=192.168.1.19!203.0.113.10' "$t37_conf" && rtpe_restart "$t37_conf" t37; then
  LO_SS_SAMPLE=1 case_run t37 uac_late_offer.xml uas_answer.xml; row T-37 ""
else
  record T-37 FAIL "the T-37 conf is not a one-line interface change, or RTPEngine did not restart on it with image $rtpe_id"
fi
negative_control t37-negative-control t37 "$(latest t01udp)"
if rtpe_restart "$conf_src" restore; then
  record rtpengine-restore PASS "RTPEngine restarted on rtpengine.conf.sipp with image $rtpe_id"
else
  record rtpengine-restore FAIL "RTPEngine did not restart on rtpengine.conf.sipp with image $rtpe_id"
fi

rows_total="$(awk '$1 ~ /^T-/ {print $1}' "$summary" | sort -u | wc -l)"
rows_failed="$(awk '$1 ~ /^T-/ && $2 == "FAIL" {print $1}' "$summary" | sort -u | wc -l)"
echo "entries: pass=$pass fail=$fail; rows: $((rows_total - rows_failed)) of $rows_total pass" | tee -a "$summary"
other_failed="$(awk '$1 !~ /^T-/ && $2 == "FAIL" {print $1}' "$summary" | sort -u | tr '\n' ' ')"
echo "non-row FAIL entries: '${other_failed}'" | tee -a "$summary"
[ "$fail" = 0 ]
