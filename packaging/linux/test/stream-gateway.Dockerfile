# The Linux package test's owner's own stock DATUM gateway: third_party/datum_gateway at the vendor commit
# (CONVOY, unmodified; context: that folder), dynamic on Debian, with the published image's xbt-supervise,
# the Stream Gateway's user (10021) and paths. packaging/linux/test/build_images.sh runs it; never published.
ARG SUPERVISE_FROM
FROM debian:bookworm-slim AS build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential cmake pkg-config \
      libjansson-dev libmicrohttpd-dev libsodium-dev libcurl4-openssl-dev >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /src
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release >/dev/null && make -C /build -j4 >/dev/null

FROM ${SUPERVISE_FROM} AS supervise

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libjansson4 libmicrohttpd12 libsodium23 libcurl4 >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/datum_gateway /usr/bin/xbt-datum-gateway
COPY --from=supervise /usr/bin/xbt-supervise /usr/bin/xbt-supervise
ENV XBT_DATA_DIR=/data
USER 10021:10021
ENTRYPOINT ["/usr/bin/xbt-supervise", "--wait", "/data/run/datum/config.json", "--watch", "/data/run/datum/rpc.cookie", "--", \
            "/usr/bin/xbt-datum-gateway", "-c", "/data/run/datum/config.json"]
