#!/usr/bin/env bash
set -uo pipefail

image="${1:?usage: t35_hop_image.sh <image> <build commit> <out dir>}"
commit="${2:?usage: t35_hop_image.sh <image> <build commit> <out dir>}"
out="${3:?usage: t35_hop_image.sh <image> <build commit> <out dir>}"
here="$(cd "$(dirname "$0")" && pwd)"
top="$(cd "$here/.." && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
baked=/opt/late_offer_hop/opensips/late_offer_hop.cfg
entry='["/opt/opensips-4.0.2/sbin/opensips","-F","-f","/opt/late_offer_hop/opensips/late_offer_hop.cfg"]'
mkdir -p "$out"
log="$out/t35.txt"
: > "$log"
verdict=PASS

note() {
  echo "$*" | tee -a "$log"
}

item() {
  note "T-35 $1 $2 $3"
  [ "$2" = PASS ] || verdict=FAIL
}

control() {
  if "$@" > /dev/null 2>&1; then echo FAIL; else echo PASS; fi
}

image_id="$(docker image inspect -f '{{.Id}}' "$image")" || { note "T-35 FAIL image '$image' not found"; exit 1; }
note "T-35 image $image id $image_id"
note "T-35 build commit $commit tree $(git -C "$repo" rev-parse "$commit^{tree}")"

version="$(docker run --rm --entrypoint /opt/opensips-4.0.2/sbin/opensips "$image" -V 2>&1)"
echo "$version" > "$out/t35_version.txt"
if grep -q '^version: opensips 4\.0\.2 ' <<< "$version"; then item "(1)" PASS "-V: $(head -1 <<< "$version")"; else item "(1)" FAIL "-V: $(head -1 <<< "$version")"; fi

baked_same() {
  docker run --rm --entrypoint cat "$image" "$baked" | cmp -s - "$1"
}
mode="$(docker run --rm --entrypoint stat "$image" -c '%a' "$baked" 2>&1)"
if baked_same "$top/opensips/late_offer_hop.cfg" && [ "$mode" = 644 ]; then r=PASS; else r=FAIL; fi
item "(2)" "$r" "baked $baked byte-identical to the worktree's late_offer_hop.cfg, read as the image user; mode '$mode'"
changed="$out/late_offer_hop.cfg.changed"
cp "$top/opensips/late_offer_hop.cfg" "$changed"
printf 'X' | dd of="$changed" bs=1 seek=0 conv=notrunc status=none
item "(2) negative control" "$(control baked_same "$changed")" "comparison against a copy with byte 0 changed must FAIL"

sipp_check() {
  docker run --rm --network host -v "$top/opensips/late_offer_hop.local.cfg.sipp:/opt/late_offer_hop/opensips/late_offer_hop.local.cfg:ro" \
    "$image" -c > "$out/t35_c_sipp.log" 2>&1
}
if sipp_check; then r=PASS; else r=FAIL; fi
item "(3)" "$r" "'<image> -c' with .sipp mounted (the .lab copies are the runner's cfg-lab-pair1/2 entries in image mode)"

inspect_ok() {
  local user ep cmd vol exp
  user="$(docker image inspect -f '{{.Config.User}}' "$1")"
  ep="$(docker image inspect -f '{{json .Config.Entrypoint}}' "$1")"
  cmd="$(docker image inspect -f '{{json .Config.Cmd}}' "$1")"
  vol="$(docker image inspect -f '{{json .Config.Volumes}}' "$1")"
  exp="$(docker image inspect -f '{{json .Config.ExposedPorts}}' "$1")"
  echo "User=$user Entrypoint=$ep Cmd=$cmd Volumes=$vol ExposedPorts=$exp"
  [ "$user" = opensips ] && [ "$ep" = "$entry" ] && [ "$cmd" = null ] && [ "$vol" = null ] && [ "$exp" = null ]
}
if fields="$(inspect_ok "$image")"; then r=PASS; else r=FAIL; fi
item "(4)" "$r" "$fields"
item "(4) negative control" "$(control inspect_ok debian:bookworm-slim)" "the same check on debian:bookworm-slim (user root) must FAIL"

key_find='find /opt \( -name "*.pem" -o -name "*.key" -o -name "id_*" \) -print'
copies="$(grep -E '^COPY' "$top/docker/opensips_rtp_engine/Dockerfile" | grep -vE '^COPY (\. /usr/src/opensips|--from=build /opt/opensips-4\.0\.2/(sbin|lib) |--chmod=0644 teammate/late_offer_hop/opensips/late_offer_hop\.cfg )')"
hits="$(docker run --rm --entrypoint sh "$image" -c "$key_find" 2>&1)"
find_rc=$?
if [ -z "$copies" ] && [ "$find_rc" = 0 ] && [ -z "$hits" ]; then r=PASS; else r=FAIL; fi
item "(5)" "$r" "other COPY lines: '${copies}'; key find under /opt (exit $find_rc): '${hits}'"
planted="$(docker run --rm --user 0 --entrypoint sh "$image" -c "touch /opt/planted.pem && $key_find")"
if [ -n "$planted" ]; then r=PASS; else r=FAIL; fi
item "(5) negative control" "$r" "the same find with a planted file reports '${planted}' (the check FAILS on it)"

note "T-35 $verdict"
[ "$verdict" = PASS ]
