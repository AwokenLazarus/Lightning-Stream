# ipstack 1.0.1, vendored with one fix

Upstream: https://github.com/narrowlink/ipstack (crate `ipstack` 1.0.1, the latest release; the same
code is on upstream `main` as of 2026-10-29).

## The bug

`IpStackTcpStream::poll_shutdown` sends the FIN only when no data is in flight. If the stream is
shut down while data is still unacknowledged, the close is parked (`Shutdown::Pending(waker)`), but
the ACK that later empties the flight only wakes the writer (`write_notify`), never the parked
shutdown. The FIN is never sent: the peer never sees the end of the stream, and a download that
ends by the server closing never ends.

## The fix (`xbt-patch.diff`)

- The packet loop gets the stream's `shutdown` state and, after `update_inflight_packet_queue`,
  wakes a pending shutdown once nothing is in flight. `poll_shutdown` then sends the FIN as before.
- `poll_shutdown`'s `Pending` arm keeps the latest waker (and returns ready if the session finished
  meanwhile), so the wake reaches the task that is polling now.

Test: `a_download_the_server_ends_by_closing_ends_on_the_phone_too` in `crates/xbt-vpn/tests/buyer.rs`
(fails on stock 1.0.1 after its 30 s deadline; passes in about 1 s with the fix).

To drop the vendored copy: once upstream releases an equivalent fix, remove `vendor/ipstack` and its
`[patch.crates-io]` line in the workspace `Cargo.toml`.
