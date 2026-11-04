# iroh-relay 1.4.1, with one patch

This is iroh-relay 1.4.1 as published on crates.io (checksum
`7e5589e7c1475700686603a970275687f760df853bc6525c7eb1347aa31d7230` in Cargo.lock before the patch),
whole. The workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`, so iroh's own
relay client builds from this copy too (the client is unchanged). It is outside the workspace's
members.

## The patch: a per-packet access hook (paid relays)

A paid Stream relay (`docs/PAID-RELAYS.md`) charges an app by the bytes it carries for it, and holds
the traffic of an app whose credit has run out until it pays. iroh-relay's access control decides
only when a client connects and sees when it leaves; it has no per-client byte count and no way to
stop or slow one client's traffic short of disconnecting it. The patch adds one hook:

- `AccessControl::on_forward(&self, src: EndpointId, dst: EndpointId, len: usize) -> Forward`, with
  a default body that returns `Forward::Yes` (so every existing implementation is unchanged), and
  the same method on `DynAccessControl` and its blanket impl. `Forward` is `#[non_exhaustive]`:
  `Yes`, `Drop`, `Hold`.
- `OnDisconnectGuard::forward(&self, dst, len) -> Forward`: calls it, `Yes` for a guard without
  access control.
- In the client actor (`server/client.rs`), a `Datagrams` frame is forwarded on `Yes`, dropped and
  counted in `send_packets_dropped` on `Drop`, and on `Hold` kept while the actor reads nothing
  more from that client and asks again every `FORWARD_HOLD_RETRY` (50 ms), for up to
  `FORWARD_HOLD_MAX` (10 s), then dropped. Writes to the client and pings go on meanwhile.
  `bytes_recv` counts every packet read. `len` is the datagrams' contents, without the relay's
  framing.
- A test, `test_relay_access_control_on_forward` in `server.rs`: a per-sender byte budget; packets
  past it are dropped while the connection stays up, held packets are forwarded in order once
  there is budget, and packets to the held client still arrive.

Everything else is as published. The same change is kept as a clean commit on iroh's own tag
`v1.4.1`, to be carried as a fork pinned by commit and offered upstream (`docs/IROH-UPSTREAM.md`);
`src/server.rs` and `src/server/client.rs` here are that commit's files.
