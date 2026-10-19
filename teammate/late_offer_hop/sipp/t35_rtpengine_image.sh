#!/usr/bin/env bash
set -uo pipefail

fork="${1:?usage: t35_rtpengine_image.sh <fork clone> <image id> <out dir>}"
image="${2:?usage: t35_rtpengine_image.sh <fork clone> <image id> <out dir>}"
out="${3:?usage: t35_rtpengine_image.sh <fork clone> <image id> <out dir>}"
mkdir -p "$out"
log="$out/t35_rtpengine.txt"
: > "$log"
verdict=PASS

note() {
  echo "$*" | tee -a "$log"
}

item() {
  note "T-35 $1 $2 $3"
  [ "$2" = PASS ] || verdict=FAIL
}

key_find='find / -xdev \( -name "*.pem" -o -name "*.key" -o -name "id_*" \) -print'

ca_re='^(/etc/ssl/certs|/usr/share/ca-certificates)/'

outside_ca() {
  grep -vE "$ca_re" <<< "$1" | grep . | tr '\n' ' '
}

fork_head="$(git -C "$fork" rev-parse --verify HEAD 2>&1)"
head_rc=$?
note "T-35 (6) rtpengine image $image fork $fork_head"
status="$(git -C "$fork" status --porcelain --ignored 2> "$out/t35_fork_status.err")"
status_rc=$?
echo "$status" > "$out/t35_fork_status.txt"
if [ "$head_rc" = 0 ] && [ "$status_rc" = 0 ] && [ -z "$status" ]; then
  item "(6) fork tree" PASS "'git status --porcelain --ignored' is empty (rev-parse exit $head_rc, status exit $status_rc)"
else
  item "(6) fork tree" FAIL "STOP: rev-parse exit $head_rc, status exit $status_rc; listed paths in t35_fork_status.txt: remove the listed paths from the fork clone and run the pass again (arch T-35 (6))"
fi

hits="$(docker run --rm --user 0 --entrypoint sh "$image" -c "$key_find")"
find_rc=$?
echo "$hits" > "$out/t35_rtpengine_find.txt"
ca_hits="$(grep -E "$ca_re" <<< "$hits")"
keyed=""
if [ -n "$ca_hits" ]; then
  keyed="$(docker run --rm -i --user 0 --entrypoint sh "$image" -c 'xargs grep -l "PRIVATE KEY"' <<< "$ca_hits" | tr '\n' ' ')"
fi
bad="$(outside_ca "$hits")$keyed"
if [ "$find_rc" = 0 ] && [ -z "$bad" ]; then r=PASS; else r=FAIL; fi
item "(6) key find" "$r" "find exit $find_rc; $(grep -c . <<< "$hits") hits (t35_rtpengine_find.txt); outside the CA directories or holding a private key:${bad:- none}"

planted="$(docker run --rm --user 0 --entrypoint sh "$image" -c "touch /usr/local/planted.pem && $key_find")"
pbad="$(outside_ca "$planted")"
if grep -qx '/usr/local/planted.pem' <<< "$planted" && [[ " $pbad " == *" /usr/local/planted.pem "* ]]; then r=PASS; else r=FAIL; fi
item "(6) negative control" "$r" "the same find with a planted file is flagged:${pbad:- nothing}"

note "T-35 (6) $verdict"
[ "$verdict" = PASS ]
