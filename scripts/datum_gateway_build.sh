#!/bin/bash
# The Stream Gateway (DATUM-compatible): third_party/datum_gateway (CONVOY 971af86 + the masking patch) as a
# static musl binary for each image platform, through zig (tools/zig-cc), like the Rust images. No system
# cross toolchain, no sudo.
#
#   scripts/datum_gateway_build.sh [--out DIR] [--targets T,T,...] [--test]
#
# Targets are zig triples: x86_64-linux-musl, aarch64-linux-musl, arm-linux-musleabihf (default: all three).
# Each one's binary is DIR/<zig triple>/xbt-datum-gateway (DIR default dist/datum). Its C dependencies are
# built static from pinned sources, each checked against its sha256 below before it is unpacked:
#   libsodium (keys, the pool link), jansson (JSON), libcurl (node RPC: http only, no TLS, no zlib),
#   libmicrohttpd (the API: no TLS), argp-standalone (musl has no argp).
# Sources are fetched once into XBT_DATUM_DEPS (default ~/.cache/xbt-datum-deps); a file already there is
# used if its hash matches. --test runs the gateway's own unit tests (--test) on the target this host runs
# (x86_64 only). The binary names no build host path: the checkout maps to /src and the build tree to /build.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=$ROOT/dist/datum
TARGETS="x86_64-linux-musl,aarch64-linux-musl,arm-linux-musleabihf"
TEST=0
while [ $# -gt 0 ]; do
  case $1 in
    --out) OUT=$2; shift 2 ;;
    --targets) TARGETS=$2; shift 2 ;;
    --test) TEST=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "datum_gateway_build: unknown option $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
CACHE=${XBT_DATUM_DEPS:-$HOME/.cache/xbt-datum-deps}
mkdir -p "$CACHE"
J=${XBT_DATUM_JOBS:-2}

# name  url  sha256
DEPS=(
  "libsodium-1.0.20.tar.gz https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19"
  "jansson-2.14.tar.gz https://github.com/akheron/jansson/releases/download/v2.14/jansson-2.14.tar.gz 5798d010e41cf8d76b66236cfb2f2543c8d082181d16bc3085ab49538d4b9929"
  "curl-8.11.1.tar.xz https://curl.se/download/curl-8.11.1.tar.xz c7ca7db48b0909743eaef34250da02c19bc61d4f1dcedd6603f109409536ab56"
  "libmicrohttpd-1.0.1.tar.gz https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.1.tar.gz|https://ftpmirror.gnu.org/libmicrohttpd/libmicrohttpd-1.0.1.tar.gz a89e09fc9b4de34dde19f4fcb4faaa1ce10299b9908db1132bbfa1de47882b94"
  "argp-standalone-1.5.0.tar.gz https://github.com/argp-standalone/argp-standalone/archive/refs/tags/1.5.0.tar.gz c29eae929dfebd575c38174f2c8c315766092cec99a8f987569d0cad3c6d64f6"
)
for d in "${DEPS[@]}"; do
  read -r name url sum <<<"$d"
  f=$CACHE/$name
  if [ ! -f "$f" ] || [ "$(sha256sum "$f" | cut -d' ' -f1)" != "$sum" ]; then
    echo "== fetch $name"
    # the url may list mirrors, |-separated: the first that serves it wins
    got=0
    IFS='|' read -r -a urls <<<"$url"
    for u in "${urls[@]}"; do
      if curl -fsSL --retry 3 --retry-delay 5 --max-time 300 -o "$f.part" "$u"; then got=1; break; fi
    done
    [ $got = 1 ] || { echo "datum_gateway_build: $name could not be fetched" >&2; exit 1; }
    mv "$f.part" "$f"
  fi
  got=$(sha256sum "$f" | cut -d' ' -f1)
  [ "$got" = "$sum" ] || { echo "datum_gateway_build: $name has sha256 $got, not $sum" >&2; rm -f "$f"; exit 1; }
done

ZIG_PY=${XBT_ZIG_PY:-$HOME/.local/share/ziglang-venv/bin/python}
"$ZIG_PY" -m ziglang version >/dev/null || { echo "datum_gateway_build: zig is missing ($ZIG_PY -m ziglang)" >&2; exit 1; }
REV=$(git rev-parse --short=12 HEAD)$(git status --porcelain --untracked-files=no | grep -q . && echo "-dirty" || true)
# what the gateway tells a pool it is (the hello's second user-agent field): upstream's commit, then ours
export XBT_DATUM_BUILD_NAME="971af86b93de+xbt-mask.$REV"

unpack() { # NAME DIR: a clean copy of a checked source in DIR
  rm -rf "$2" && mkdir -p "$2"
  tar xf "$CACHE/$1" -C "$2" --strip-components=1
}

IFS=, read -r -a TS <<<"$TARGETS"
for T in "${TS[@]}"; do
  case $T in
    x86_64-linux-musl) PROC=x86_64 ;;
    aarch64-linux-musl) PROC=aarch64 ;;
    arm-linux-musleabihf) PROC=armv7l ;;
    *) echo "datum_gateway_build: unknown target $T" >&2; exit 2 ;;
  esac
  echo "== $T"
  W=$OUT/work/$T
  P=$W/prefix
  rm -rf "$W" && mkdir -p "$P/lib" "$P/include"
  export XBT_ZIG_TARGET=$T
  export CC="$ROOT/tools/zig-cc" AR="$ROOT/tools/zig-ar" RANLIB=true
  export CFLAGS="-O2 -ffile-prefix-map=$ROOT=/src -ffile-prefix-map=$OUT=/build"
  export LDFLAGS="-static"
  export PKG_CONFIG_LIBDIR=$P/lib/pkgconfig PKG_CONFIG_PATH=
  log=$W/build.log
  AC=(--host="$T" --prefix="$P" --enable-static --disable-shared)

  unpack libsodium-1.0.20.tar.gz "$W/sodium"
  (cd "$W/sodium" && ./configure "${AC[@]}" --disable-pie >>"$log" 2>&1 && make -j"$J" install >>"$log" 2>&1) \
    || { tail -30 "$log" >&2; echo "datum_gateway_build: libsodium failed for $T ($log)" >&2; exit 1; }

  unpack jansson-2.14.tar.gz "$W/jansson"
  (cd "$W/jansson" && ./configure "${AC[@]}" >>"$log" 2>&1 && make -j"$J" install >>"$log" 2>&1) \
    || { tail -30 "$log" >&2; echo "datum_gateway_build: jansson failed for $T ($log)" >&2; exit 1; }

  unpack curl-8.11.1.tar.xz "$W/curl"
  (cd "$W/curl" && ./configure "${AC[@]}" --without-ssl --without-zlib --without-brotli --without-zstd \
      --without-libpsl --without-libidn2 --without-nghttp2 --without-nghttp3 --without-ngtcp2 --without-librtmp \
      --without-libssh2 --without-libssh --without-gssapi --without-ca-bundle --without-ca-path \
      --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 \
      --disable-imap --disable-smtp --disable-gopher --disable-mqtt --disable-smb --disable-ftp --disable-file \
      --disable-ntlm --disable-manual --disable-docs --disable-websockets --enable-threaded-resolver \
      >>"$log" 2>&1 && make -j"$J" install >>"$log" 2>&1) \
    || { tail -30 "$log" >&2; echo "datum_gateway_build: curl failed for $T ($log)" >&2; exit 1; }

  unpack libmicrohttpd-1.0.1.tar.gz "$W/mhd"
  (cd "$W/mhd" && ./configure "${AC[@]}" --disable-https --disable-doc --disable-examples --disable-tools \
      --without-gnutls --disable-curl >>"$log" 2>&1 && make -j"$J" install >>"$log" 2>&1) \
    || { tail -30 "$log" >&2; echo "datum_gateway_build: libmicrohttpd failed for $T ($log)" >&2; exit 1; }

  # argp-standalone ships no configure: its seven sources, with what musl has said plainly
  unpack argp-standalone-1.5.0.tar.gz "$W/argp"
  cat > "$W/argp/config.h" <<'EOF'
#define HAVE_ALLOCA_H 1
#define HAVE_LIMITS_H 1
#define HAVE_MALLOC_H 1
#define HAVE_UNISTD_H 1
#define HAVE_FLOCKFILE 1
#define HAVE_FUNLOCKFILE 1
#define HAVE_DECL_FLOCKFILE 1
#define HAVE_DECL_FPUTS_UNLOCKED 1
#define HAVE_DECL_FPUTC_UNLOCKED 1
#define HAVE_DECL_FWRITE_UNLOCKED 1
#define HAVE_DECL_PUTC_UNLOCKED 1
#define HAVE_MEMPCPY 1
#define HAVE_ASPRINTF 1
#define HAVE_STRCHRNUL 1
#define HAVE_STRNDUP 1
#define HAVE_STRCASECMP 1
#define HAVE_DECL_PROGRAM_INVOCATION_NAME 1
#define HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME 1
/* what argp's own configure adds (meson_config.h.in): its sources use these */
#define NORETURN __attribute__ ((__noreturn__))
#define PRINTF_STYLE(f, a) __attribute__ ((__format__ (__printf__, f, a)))
#define UNUSED __attribute__ ((__unused__))
EOF
  (cd "$W/argp" && for c in argp-ba argp-eexst argp-fmtstream argp-help argp-parse argp-pv argp-pvh; do
      "$CC" $CFLAGS -D_GNU_SOURCE -DHAVE_CONFIG_H=1 -I. -c "$c.c" -o "$c.o" || exit 1
    done && "$AR" rcs "$P/lib/libargp.a" argp-*.o && cp argp.h "$P/include/") >>"$log" 2>&1 \
    || { tail -30 "$log" >&2; echo "datum_gateway_build: argp failed for $T ($log)" >&2; exit 1; }

  # the gateway, against those alone (CMAKE_FIND_ROOT_PATH: no host library is found). Linked without debug
  # info: zig builds its musl libc once into its own cache, with that build's working directory and zig's own
  # install path in the DWARF (no -ffile-prefix-map reaches it), and those are host paths
  B=$W/gw
  (cmake -S "$ROOT/third_party/datum_gateway" -B "$B" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$PROC" \
      -DCMAKE_C_COMPILER="$ROOT/tools/zig-cc" -DCMAKE_AR="$ROOT/tools/zig-ar" -DCMAKE_RANLIB=/bin/true \
      -DCMAKE_FIND_ROOT_PATH="$P" -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
      -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
      -DARGP_INCLUDE_DIR="$P/include" -DARGP_LIBRARY="$P/lib/libargp.a" \
      -DCMAKE_C_FLAGS="$CFLAGS -ffile-prefix-map=$B=/build" -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--strip-debug" >>"$log" 2>&1 \
    && cmake --build "$B" -j"$J" >>"$log" 2>&1) \
    || { tail -40 "$log" >&2; echo "datum_gateway_build: the gateway failed for $T ($log)" >&2; exit 1; }

  mkdir -p "$OUT/$T"
  cp "$B/datum_gateway" "$OUT/$T/xbt-datum-gateway"
  f=$OUT/$T/xbt-datum-gateway
  file -b "$f" | grep -q "statically linked" || { echo "datum_gateway_build: $f is not static: $(file -b "$f")" >&2; exit 1; }
  if grep -q -a -F -e "$ROOT/" -e "$OUT/" "$f"; then
    echo "datum_gateway_build: $f names a build host path" >&2; exit 1
  fi
  echo "== $T: $(file -b "$f" | cut -d, -f1-2), $(stat -c %s "$f") bytes, sha256 $(sha256sum "$f" | cut -c1-16)"
  if [ $TEST = 1 ] && [ "$T" = x86_64-linux-musl ] && [ "$(uname -m)" = x86_64 ]; then
    echo "== $T: the gateway's unit tests"
    (cd "$W" && "$f" --test) >"$W/test.log" 2>&1 || { tail -30 "$W/test.log" >&2; echo "datum_gateway_build: unit tests failed ($W/test.log)" >&2; exit 1; }
    tail -3 "$W/test.log"
  fi
done
# what the image ships beside the binary (usr/share/xbt-datum-gateway): our notice, the gateway's licence and
# each statically linked library's (libmicrohttpd and argp-standalone are LGPL: the notice says where the
# source and this script are, so the binary can be rebuilt and relinked)
L=$OUT/licenses
rm -rf "$L" && mkdir -p "$L"
cp "$ROOT/container/datum-gateway-NOTICE" "$L/NOTICE"
cp "$ROOT/third_party/datum_gateway/LICENSE" "$L/datum_gateway.LICENSE"
tar xOf "$CACHE/libsodium-1.0.20.tar.gz" libsodium-1.0.20/LICENSE > "$L/libsodium.LICENSE"
tar xOf "$CACHE/jansson-2.14.tar.gz" jansson-2.14/LICENSE > "$L/jansson.LICENSE"
tar xOf "$CACHE/curl-8.11.1.tar.xz" curl-8.11.1/COPYING > "$L/curl.COPYING"
tar xOf "$CACHE/libmicrohttpd-1.0.1.tar.gz" libmicrohttpd-1.0.1/COPYING > "$L/libmicrohttpd.COPYING"
# argp-standalone ships no licence file: its sources' own notice (GNU Library GPL, version 2 or later)
tar xOf "$CACHE/argp-standalone-1.5.0.tar.gz" argp-standalone-1.5.0/argp-parse.c | sed -n '1,/\*\//p' > "$L/argp-standalone.NOTICE"
for f in "$L"/*; do [ -s "$f" ] || { echo "datum_gateway_build: $f is empty" >&2; exit 1; }; done
echo "datum_gateway_build: OK ($XBT_DATUM_BUILD_NAME)"
