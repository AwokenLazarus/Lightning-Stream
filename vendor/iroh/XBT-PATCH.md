# iroh 1.4.1, with one patch

This is iroh 1.4.1 as published on crates.io (checksum
`see Cargo.lock history`), whole. The workspace uses it through `[patch.crates-io]` in
the root `Cargo.toml`. It is outside the workspace's members; test it on its own with
`cargo test --manifest-path vendor/iroh/Cargo.toml --lib test_add_report_history_set_preferred_relay`.

## The patch: a preferred home relay

iroh makes the relay that answers fastest its home relay, and a relay map is also where iroh learns
its own public address (QUIC address discovery, which needs UDP to the relay). A relay that cannot
take UDP (ours: its host's provider drops inbound UDP) therefore can neither find addresses nor,
when a faster relay is in the map for that, stay home. The patch lets a caller name the relay to
make home whenever it answers; the other relays in the map are still probed, so their address
discovery still works. When the preferred relay does not answer, the home relay is chosen by
latency as before, which is the fallback.

- `NetReportConfig::preferred_relay: Option<RelayUrl>` (the struct is `#[non_exhaustive]`, so this
  is not a breaking change), `None` in `default()` and `minimal()`.
- `net_report::Client` keeps it, and `add_report_history_and_set_preferred_relay` sets
  `preferred_relay` to it when it is among the relays that answered in the report.
- A test in `test_add_report_history_set_preferred_relay`: a slow preferred relay is home while it
  answers; when it does not, another is.

Everything else is as published. Meant to be offered upstream as is.
