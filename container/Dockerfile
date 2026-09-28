# AGP-038: the agentpay images, one per binary, FROM scratch (docs/CONTAINER.md).
# Built by scripts/oci_build.sh with docker buildx for linux/amd64, linux/arm64 and linux/arm/v7 from the
# static musl binaries it stages under bin/<arch>/. There is no RUN, so no emulator is needed.
# Layer 1 (base.tar: passwd/group, /tmp, the /data skeleton with each component's owner) is byte-identical
# in all four images and stored once. Layer 2 is the binary.
# No `# syntax=` line: the builder's built-in frontend, nothing pulled.

FROM scratch AS base
ADD base.tar /
ENV XBT_DATA_DIR=/data XBT_MODE=production

FROM base AS xbt-signer
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-signer /usr/bin/xbt-signer
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

FROM base AS xbt402-hub
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt402-hub /usr/bin/xbt402-hub
EXPOSE 9480
USER xbt402-hub
ENTRYPOINT ["/usr/bin/xbt402-hub"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt402-hub", "healthcheck"]
