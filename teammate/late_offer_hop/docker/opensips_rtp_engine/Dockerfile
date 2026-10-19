FROM debian:bookworm AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev make flex bison pkg-config libssl-dev libncurses-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . /usr/src/opensips
WORKDIR /usr/src/opensips

RUN make all prefix=/opt/opensips-4.0.2 LIBDIR=lib \
 && make install prefix=/opt/opensips-4.0.2 LIBDIR=lib

FROM debian:bookworm-slim

COPY --from=build /opt/opensips-4.0.2/sbin /opt/opensips-4.0.2/sbin
COPY --from=build /opt/opensips-4.0.2/lib /opt/opensips-4.0.2/lib
RUN useradd --system --no-create-home --shell /usr/sbin/nologin opensips \
 && mkdir -p /opt/late_offer_hop/opensips

COPY --chmod=0644 teammate/late_offer_hop/opensips/late_offer_hop.cfg /opt/late_offer_hop/opensips/late_offer_hop.cfg

USER opensips

ENTRYPOINT ["/opt/opensips-4.0.2/sbin/opensips", "-F", "-f", "/opt/late_offer_hop/opensips/late_offer_hop.cfg"]
