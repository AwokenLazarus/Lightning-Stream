# Our iroh patches: the fork, and the offer upstream

Lightning Stream builds on iroh 1.4.1 with two small patches. Until 0.3.0 they were carried as
whole vendored copies of the published crates (`vendor/iroh`, `vendor/iroh-relay`, each with an
`XBT-PATCH.md`). From 0.3.0 they are carried as a fork of iroh's own repository, pinned by commit,
and offered upstream as two small, generic changes.

## The fork

- Repository: `https://github.com/AwokenLazarus/iroh` (a fork of `n0-computer/iroh`).
- Branch `xbt/relay-forward-hook-v1.4.1`, based on iroh's tag `v1.4.1` (`d6c6963b96`, the
  release the vendored copies came from), with two commits:

| Commit | Crate | Change |
| --- | --- | --- |
| `c76b2b34ba` | iroh-relay | `AccessControl::on_forward`, a hook for each relayed packet (paid relays, `docs/PAID-RELAYS.md`), with a test |
| `e4b6ac6af1` | iroh | `NetReportConfig::preferred_relay`, a preferred home relay (ours, which cannot take UDP) |

Nothing else differs from the tag. The vendored files `vendor/iroh-relay/src/server.rs`,
`vendor/iroh-relay/src/server/client.rs` and `vendor/iroh/src/net_report.rs` are those commits'
files, and the rest of each vendored copy is the tag's (iroh-base and iroh-dns at the tag are the
published 1.4.1 too).

The workspace takes all four crates from the same commit, so it has one copy of each:

```toml
[patch.crates-io]
iroh = { git = "https://github.com/AwokenLazarus/iroh", rev = "e4b6ac6af10634abd27adfd7d2919a07d8e78900" }
iroh-base = { git = "https://github.com/AwokenLazarus/iroh", rev = "e4b6ac6af10634abd27adfd7d2919a07d8e78900" }
iroh-dns = { git = "https://github.com/AwokenLazarus/iroh", rev = "e4b6ac6af10634abd27adfd7d2919a07d8e78900" }
iroh-relay = { git = "https://github.com/AwokenLazarus/iroh", rev = "e4b6ac6af10634abd27adfd7d2919a07d8e78900" }
```

The switch is one commit ("Carry the iroh patches as a fork pinned by commit"): these lines in
place of the two `path` lines, `vendor/iroh` and `vendor/iroh-relay` removed, and `Cargo.lock`
changed only in the four packages' `source` lines (their dependencies are the same). It is
applied once the fork is pushed: before that, cargo cannot fetch it. CI's `cargo fetch --locked`
then fetches the fork like any git dependency.

If the hook changes before it is offered (for example a third answer, holding a packet rather
than dropping it), the fork gets a new commit and the `rev` above moves with it.

## The offer upstream

iroh asks that every pull request link to an issue that maintainers have discussed and labeled
`ready-for-pr` (their `CONTRIBUTING.md` and `AI_POLICY.md`), and that issues read as a
conversation between people, with anything machine-written folded under `<details>`. So the offer
starts as an issue, opened and discussed by a person. Below are drafts to edit, not to paste.

Each change also applies cleanly to iroh's `main` (1.5.0 at the time of writing); the pull request
would be made from there.

### Issue 1 (iroh-relay): a per-packet hook in `AccessControl`

> **Title:** iroh-relay: let `AccessControl` see (and refuse) each relayed packet
>
> We are building iroh relays that charge for what they carry, by the byte, per endpoint. `AccessControl`
> decides when a client connects and is told when it leaves, but there is no way to count what
> the relay carries for an endpoint, or to stop carrying one endpoint's traffic without
> disconnecting it (it should stay connected, so it is carried again as soon as it pays).
>
> Would you take a small hook for this? What we have now is:
>
> ```rust
> trait AccessControl {
>     // ...
>     /// Whether one relayed packet is forwarded: `len` bytes of datagrams from the admitted
>     /// client `src` to `dst`. The default forwards everything. Must not block.
>     fn on_forward(&self, src: EndpointId, dst: EndpointId, len: usize) -> bool { true }
> }
> ```
>
> The client actor calls it for each `Datagrams` frame before forwarding it; a refused packet is
> dropped and counted in `send_packets_dropped`. Existing implementations are unchanged. Other uses
> we can think of: quotas on a public relay, per-key fair use, accounting for a relay shared by
> teams.
>
> Happy to change the shape (a richer return type, a separate trait, a feature flag) if you'd
> prefer. We'd send the PR ourselves.
>
> <details><summary>Details</summary>
>
> - `AccessControl::on_forward` with a default body, the same method on `DynAccessControl` and its
>   blanket impl, and `OnDisconnectGuard::forward(dst, len)` (true without access control).
> - In `server/client.rs`, `handle_frame` forwards a `Datagrams` frame only when the guard says
>   so. `bytes_recv` still counts it. `len` is the datagrams' contents, without framing.
> - The call is synchronous and on the client actor's task, once per packet; an implementation
>   keeps it to a lock and a few additions.
> - A test, `test_relay_access_control_on_forward`: a per-sender byte budget; packets past it are
>   not forwarded, the connection stays up, and forwarding resumes when the budget is raised.
> - About 30 lines plus the test.
>
> </details>

### Issue 2 (iroh): a preferred home relay

> **Title:** iroh: let the net report prefer one relay as home while it answers
>
> We give our endpoints a relay map with our own relay and some public ones. Ours can't take UDP
> (the host's provider drops inbound UDP), so the public relays are what QUIC address discovery
> runs against, and one of them is usually faster to answer, so it becomes home. We want ours to
> be home whenever it answers, while the others are still probed for address discovery.
>
> Would an optional `NetReportConfig::preferred_relay: Option<RelayUrl>` be welcome? When set, the
> net report makes that relay the preferred one whenever it is among the relays that answered, and
> otherwise chooses by latency as today. The struct is `#[non_exhaustive]`, so it isn't breaking.
>
> <details><summary>Details</summary>
>
> - `NetReportConfig::preferred_relay`, `None` in `default()` and `minimal()`.
> - `net_report::Client` keeps it; `add_report_history_and_set_preferred_relay` sets the report's
>   preferred relay to it when it answered, and a report waits for its latency probe before it is
>   good enough (it can come later than the other relays' address discovery).
> - A test, `test_add_report_history_set_preferred_relay`: a slow preferred relay is home while it
>   answers; when it has not answered for a while, another is.
>
> </details>

### The pull requests (once an issue is labeled `ready-for-pr`)

Titles in iroh's form, opened as drafts against `main`:

- `feat(iroh-relay): add an AccessControl::on_forward hook for each relayed packet`, body:
  `Refs #<issue>`, a two-line summary, and the details above under `<details>`.
- `feat(iroh): let NetReportConfig name a preferred home relay`, the same way.

When a change is released upstream, the fork's commit for it is dropped and the `rev` moves to a
release that has it; when both are, the `[patch.crates-io]` lines for iroh go away.
