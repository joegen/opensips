#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <rtpengine.conf path> <rtpengine fork clone path>" >&2
  exit 2
fi

conf="$1"
fork="$2"
mount_src=/opt/late_offer_hop/rtpengine/rtpengine.conf

install -m 0644 "$conf" "$mount_src"

if docker container inspect rtpengine-lo >/dev/null 2>&1; then
  docker rm -f rtpengine-lo >/dev/null
fi

docker build -t rtpengine-lo:mr27.0.0.0 "$fork"

docker run -d --name rtpengine-lo --network host \
  --entrypoint /usr/local/bin/rtpengine \
  -v /opt/late_offer_hop/rtpengine/rtpengine.conf:/etc/rtpengine-lo/rtpengine.conf:ro \
  rtpengine-lo:mr27.0.0.0 \
  --config-file=/etc/rtpengine-lo/rtpengine.conf --foreground --log-stderr
