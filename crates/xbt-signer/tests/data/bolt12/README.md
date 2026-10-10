# BOLT 12 spec test vectors

`format-string-test.json`, `offers-test.json` and `signature-test.json` are the BOLT 12 test vectors of
the Lightning specification, unchanged.

- Source: `bolt12/` in [lightning/bolts](https://github.com/lightning/bolts), commit
  `311119388a46dfa859da3d2eda0ca836cfc5f078`, as vendored by Lightning Fork
  (`bolt12/test-vectors/` at `v0.21.3-beta-blake2b.17`).
- License: Creative Commons Attribution 4.0 International (CC-BY 4.0).

`crates/xbt-signer/src/bolt12.rs` is checked against them (AGP-082). They carry no feature bit 512: they
test the reader, not what the rail will pay.
