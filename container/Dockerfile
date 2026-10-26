# The images, one per service, FROM scratch (docs/CONTAINER.md): the signer, the anchor witness, the MCP
# server, the wallet UI, xbt-init (the one-shot that fixes a bind mount's owners before the services
# start), xbt-work-relay (the blinded receipt relay of pay-with-work), xbt-gateway (the seller gateway),
# lightning-stream (the connector) and xbt-hashlink (p2p-hash).
# Built by scripts/oci_build.sh with docker buildx for linux/amd64, linux/arm64 and linux/arm/v7 from the
# static musl binaries it stages under bin/<arch>/. There is no RUN, so no emulator is needed.
# Layer 1 (base.tar: passwd/group, /tmp, the /data skeleton with each component's owner) is byte-identical
# in all the images and stored once. Layer 2 is the binary (the signer and the gateway: with xbt-supervise
# beside it, from bin/<arch>/<image>.d/).
# No `# syntax=` line: the builder's built-in frontend, nothing pulled.

ARG IMAGE=xbt-signer

FROM scratch AS base
ADD base.tar /
ENV XBT_DATA_DIR=/data XBT_MODE=production

# xbt-supervise rides along: a package runs the signer under it, so a rail macaroon the UI writes
# restarts the signer (packaging/DESIGN.md). The image's own entrypoint is the signer alone.
FROM base AS xbt-signer
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-signer.d/ /usr/bin/
USER xbt-signer
ENTRYPOINT ["/usr/bin/xbt-signer"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt-signer", "healthcheck"]

FROM base AS xbt-anchor-witness
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-anchor-witness /usr/bin/xbt-anchor-witness
USER xbt-anchor-witness
ENTRYPOINT ["/usr/bin/xbt-anchor-witness"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-anchor-witness", "healthcheck"]

FROM base AS xbt-wallet-mcp
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-wallet-mcp /usr/bin/xbt-wallet-mcp
ENV XBT_MCP_HTTP=0.0.0.0:33510
EXPOSE 33510
USER xbt-wallet-mcp
ENTRYPOINT ["/usr/bin/xbt-wallet-mcp"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-wallet-mcp", "--healthcheck"]

FROM base AS xbt-wallet-ui
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-wallet-ui /usr/bin/xbt-wallet-ui
ENV XBT_UI_BIND=0.0.0.0:8480
EXPOSE 8480
USER xbt-wallet-ui
ENTRYPOINT ["/usr/bin/xbt-wallet-ui"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-wallet-ui", "healthcheck"]

# AGP-043: the xbt-work blinded receipt relay. 9490 is the public, read-only listener; 9491 takes the Prime's pushes
# and must stay on a private network (set the relay-push-token secret, or XBT_RELAY_PUSH_ALLOW_OPEN=1 when only the
# Prime can reach it). Blobs live under /data/relay/blobs.
FROM base AS xbt-work-relay
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-work-relay /usr/bin/xbt-work-relay
ENV XBT_RELAY_BIND=0.0.0.0:9490 XBT_RELAY_PUSH_BIND=0.0.0.0:9491
EXPOSE 9490 9491
USER xbt-work-relay
ENTRYPOINT ["/usr/bin/xbt-work-relay"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD ["/usr/bin/xbt-work-relay", "healthcheck"]

# The stream-ticket seller gateway. It reads one config file, which the UI's gateway page writes into
# /data/run/gateway; xbt-supervise starts the gateway once that file exists and again when it or a
# macaroon changes. 8402 is for buyers, behind an https proxy (the gateway refuses a non-loopback
# listen without an https public_url). State: /data/gateway.
FROM base AS xbt-gateway
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-gateway.d/ /usr/bin/
EXPOSE 8402
USER xbt-gateway
ENTRYPOINT ["/usr/bin/xbt-supervise", "--wait", "/data/run/gateway/config.json", "--watch", "/data/run/gateway/invoices.macaroon", \
            "--watch", "/data/run/gateway/info.macaroon", "--watch", "/data/lightning/tls.cert", "--", \
            "/usr/bin/xbt-gateway", "/data/run/gateway/config.json"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt-supervise", "probe", "http://127.0.0.1:8402/x402/ticket/health"]

# The connector. A local player asks it for a seller's URL; the signer pays and streams the body.
# It holds no keys. USER is the signer's user: the sockets it binds have to be ones that user can
# connect to, and the published signer image cannot gain a group until it is rebuilt. Loopback only.
FROM base AS lightning-stream
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/lightning-stream /usr/bin/lightning-stream
USER xbt-signer
ENV LS_LISTEN=127.0.0.1:8484
ENTRYPOINT ["/usr/bin/lightning-stream"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/lightning-stream", "healthcheck"]

# p2p-hash: the hasher's service (miners in, renters' links in, paid pieces of work in) and the
# renter's (offers from Nostr, rentals into the owner's DATUM Gateway, paid through the signer: its
# user is in the signer's group for the socket). One binary, xbt-hashlink, run as xbt-hashrate.
FROM base AS xbt-hashlink
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-hashlink /usr/bin/xbt-hashlink
USER xbt-hashrate
ENTRYPOINT ["/usr/bin/xbt-hashlink"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-hashlink", "healthcheck"]

# The one image that runs as root: it exits once the data dir's owners and modes are right. Run it with
# cap_drop ALL + CHOWN, FOWNER, DAC_OVERRIDE, no network, read-only (docs/CONTAINER.md §7).
FROM base AS xbt-init
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-init /usr/bin/xbt-init
USER 0:0
ENTRYPOINT ["/usr/bin/xbt-init"]
CMD ["init"]
HEALTHCHECK NONE

# `--build-arg IMAGE=<name>` without `--target` builds that one image (the ARG is at the top): for a
# builder with no target option. scripts/oci_build.sh uses --target.
FROM ${IMAGE} AS selected
