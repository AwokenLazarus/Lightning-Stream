#!/usr/bin/env python3
"""AGP-038: write base.tar, the image layer shared by every agentpay image (docs/CONTAINER.md).

Deterministic (mtime 0, sorted, numeric owners) so the layer digest is the same on every build. It holds:
  /etc/passwd, /etc/group   the service users; each socket group lists its clients (xbt-signer is in
                            xbt-anchor-witness's group; xbt-wallet-mcp and xbt-wallet-ui are in xbt-signer's;
                            xbt-wallet-mcp is in xbt-wallet-ui's, to read the UI-owned MCP token, AGP-042)
  /tmp                      1777 (a tmpfs in compose; the root filesystem is read-only)
  /data/<component>         0700, owned by the component (a named volume mounted here inherits this)
  /data/run/signer, /data/run/anchor   0750, the socket dirs (owner = the server, group = its clients)
  /data/run/ui      0750, the UI's shared dir: mcp-http-token (0640), which the MCP only reads (AGP-042)
  /data/gateway     0700, the seller gateway's state (xbt-gateway, 10007)
  /data/run/ln      0750 xbt-wallet-ui:xbt-ln-rail, the wallet's rail macaroon the UI's Lightning page writes;
                    the group (10008, a group only) has the signer and the UI in it, never the MCP
  /data/run/gateway 0750 xbt-wallet-ui:xbt-gateway, the gateway's config and macaroons the UI's gateway page writes
  /data/run/enroll  0750 xbt-signer:xbt-enroll, the signer's enrolment code for the UI's setup page; the group
                    (10009, a group only) has the signer and the UI in it, never the MCP
  /data/hashrate    0700, the hashrate services' keys and state (xbt-hashrate, 10010)
  /data/run/shops   0750 xbt-wallet-ui:xbt-signer, the shops without a web address the UI keeps (public data);
                    the connector (the signer's user) and the MCP (in its group) read it
  /data/run/hashrate 0750 xbt-wallet-ui:xbt-hashrate, their settings the UI's Hashrate page writes, and their control token
  /data/stream-relay 0700, the built-in Stream relay's certificates and attempt log (xbt-stream-relay, 10016)
  /data/run/relay   0750 xbt-wallet-ui:xbt-stream-relay, the owner's relay settings the UI's Stream relays page writes
  /data/run/relay-status 0750 xbt-stream-relay:xbt-relay-status, the relay's status for the UI; the group
                    (10017, a group only) has the relay and the UI in it
  /data/vpn         0700, the VPN service's keys (WireGuard, the exit's link, Nostr) and category lists (xbt-vpn, 10018)
  /data/run/vpn     0750 xbt-wallet-ui:xbt-vpn, the devices and exit the UI's VPN pages write
  /data/run/vpn-status 0750 xbt-vpn:xbt-vpn-status, the VPN service's status for the UI; the group
                    (10019, a group only) has the service and the UI in it
  /data/run/signer/streams 0770 xbt-signer:xbt-streams where the VPN service is installed (else 0750, the
                    signer's): the sockets streamed answers go to; the VPN service (in xbt-signer's group, to
                    reach the signer's socket) makes each paid tunnel's there. The group (10020, a group only)
                    has the signer and the VPN service in it
  /data/run/ai      0770 xbt-wallet-ui:xbt-ai, the AI endpoint's files: the credential store (AI keys and local links)
                    both the UI and the connector (which runs as the signer's user) write, the sellers the UI's AI
                    page writes, and the sellers' health the endpoint writes; the group (10014, a group only; 10011 to 10013 are reserved for xbt-compute) has
                    the signer and the UI in it, never the MCP
  xbt-shared-files (1000, a group only) has the UI in it: the gid another app's files carry when the Files
                    service shares them read-only (File Browser's on StartOS, Umbrel's Downloads)
Uid 10004 is not used: it was the retired hub's, and the other uids keep their numbers.
    python3 container/mkbase.py OUT.tar
"""
import io
import sys
import tarfile

USERS = [("xbt-signer", 10001), ("xbt-anchor-witness", 10002), ("xbt-wallet-mcp", 10003), ("xbt-wallet-ui", 10005),
         ("xbt-work-relay", 10006), ("xbt-gateway", 10007), ("xbt-hashrate", 10010), ("xbt-stream-relay", 10016), ("xbt-vpn", 10018)]
HOME = {"xbt-signer": "/data/signer", "xbt-anchor-witness": "/data/witness", "xbt-wallet-mcp": "/data/mcp",
        "xbt-wallet-ui": "/data/ui", "xbt-work-relay": "/data/relay", "xbt-gateway": "/data/gateway", "xbt-hashrate": "/data/hashrate",
        "xbt-stream-relay": "/data/stream-relay", "xbt-vpn": "/data/vpn"}
MEMBERS = {"xbt-signer": "xbt-wallet-mcp,xbt-wallet-ui,xbt-hashrate,xbt-vpn", "xbt-anchor-witness": "xbt-signer", "xbt-wallet-ui": "xbt-wallet-mcp",
           "xbt-gateway": "xbt-wallet-ui", "xbt-hashrate": "xbt-wallet-ui", "xbt-stream-relay": "xbt-wallet-ui", "xbt-vpn": "xbt-wallet-ui"}
# groups with no user of their own
GROUPS = [("xbt-ln-rail", 10008, "xbt-signer,xbt-wallet-ui"), ("xbt-enroll", 10009, "xbt-signer,xbt-wallet-ui"),
          ("xbt-relay-status", 10017, "xbt-stream-relay,xbt-wallet-ui"),
          ("xbt-vpn-status", 10019, "xbt-vpn,xbt-wallet-ui"),
          ("xbt-ai", 10014, "xbt-signer,xbt-wallet-ui"),
          ("xbt-streams", 10020, "xbt-signer,xbt-vpn"),
          # files another app keeps for the owner, mounted read-only for the Files service: File Browser on
          # StartOS writes them as 1000:1000 with 0640/0750 (and Umbrel's Downloads are 1000's too); the UI
          # reads them through this group. StartOS 0.4.0.1 does not apply a mount's idmap, so this is how
          # they are readable there at all; the mount stays read-only
          ("xbt-shared-files", 1000, "xbt-wallet-ui")]

passwd = "root:x:0:0:root:/:/nonexistent\n" + "".join(f"{n}:x:{u}:{u}:{n}:{HOME[n]}:/nonexistent\n" for n, u in USERS)
group = ("root:x:0:\n" + "".join(f"{n}:x:{u}:{MEMBERS.get(n, '')}\n" for n, u in USERS)
         + "".join(f"{n}:x:{g}:{m}\n" for n, g, m in GROUPS))

DIRS = [("etc", 0, 0, 0o755), ("tmp", 0, 0, 0o1777), ("usr", 0, 0, 0o755), ("usr/bin", 0, 0, 0o755), ("data", 0, 0, 0o755),
        # made here, not by COPY: a COPY --chmod=0444 that creates its destination folder gives the folder 0444
        # too, and the VPN service (uid 10018) could then not reach its country table (exits' regions unverified)
        ("usr/share", 0, 0, 0o755), ("usr/share/xbt-vpn", 0, 0, 0o555),
        ("data/signer", 10001, 10001, 0o700), ("data/witness", 10002, 10002, 0o700), ("data/mcp", 10003, 10003, 0o700),
        ("data/ui", 10005, 10005, 0o700), ("data/relay", 10006, 10006, 0o700), ("data/gateway", 10007, 10007, 0o700), ("data/hashrate", 10010, 10010, 0o700), ("data/run", 0, 0, 0o755), ("data/run/signer", 10001, 10001, 0o750),
        ("data/run/anchor", 10002, 10002, 0o750), ("data/run/ui", 10005, 10005, 0o750),
        ("data/run/ln", 10005, 10008, 0o750), ("data/run/gateway", 10005, 10007, 0o750), ("data/run/enroll", 10001, 10009, 0o750),
        ("data/run/hashrate", 10005, 10010, 0o750),
        ("data/run/shops", 10005, 10001, 0o750),
        ("data/stream-relay", 10016, 10016, 0o700), ("data/run/relay", 10005, 10016, 0o750), ("data/run/relay-status", 10016, 10017, 0o750), ("data/run/ai", 10005, 10014, 0o770),
        ("data/vpn", 10018, 10018, 0o700), ("data/run/vpn", 10005, 10018, 0o750), ("data/run/vpn-status", 10018, 10019, 0o750)]
FILES = [("etc/passwd", passwd, 0o644), ("etc/group", group, 0o644)]

entries = []
for path, uid, gid, mode in DIRS:
    t = tarfile.TarInfo(path)
    t.type, t.uid, t.gid, t.mode = tarfile.DIRTYPE, uid, gid, mode
    entries.append((t, None))
for path, text, mode in FILES:
    t = tarfile.TarInfo(path)
    data = text.encode()
    t.size, t.mode = len(data), mode
    entries.append((t, data))
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT) as tar:
    for t, data in sorted(entries, key=lambda e: e[0].name):
        t.mtime, t.uname, t.gname = 0, "", ""
        tar.addfile(t, io.BytesIO(data) if data is not None else None)
