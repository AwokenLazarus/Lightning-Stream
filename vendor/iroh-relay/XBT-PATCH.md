# iroh-relay 1.4.1, with one patch

This is iroh-relay 1.4.1 as published on crates.io (checksum
`7e5589e7c1475700686603a970275687f760df853bc6525c7eb1347aa31d7230` in Cargo.lock before the patch),
whole. The workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`, so iroh's own
relay client builds from this copy too (the client is unchanged). It is outside the workspace's
members.

## The patch: a per-packet access hook (paid relays)

A paid Stream relay (`docs/PAID-RELAYS.md`) charges a shop by the bytes it carries for it and stops
carrying for a shop whose credit has run out. iroh-relay's access control decides only when a
client connects and sees when it leaves; it has no per-client byte count and no way to stop one
client's traffic short of disconnecting it. The patch adds one hook:

- `AccessControl::on_forward(&self, src: EndpointId, dst: EndpointId, len: usize) -> bool`, with a
  default body that returns `true` (so every existing implementation is unchanged), and the same
  method on `DynAccessControl` and its blanket impl.
- `OnDisconnectGuard::forward(&self, dst, len) -> bool`: calls it, `true` for a guard without access
  control.
- In the client actor (`server/client.rs`, `handle_frame`), a `Datagrams` frame is forwarded only when
  `guard.forward(dst, len)` says so; otherwise it is dropped and counted in `send_packets_dropped`.
  `bytes_recv` still counts it. `len` is the datagrams' contents, without the relay's framing.

Everything else is as published. Meant to be offered upstream as is.
