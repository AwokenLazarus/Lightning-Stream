# ureq 2.12.1, with one patch

This is the `src/` of ureq 2.12.1 as published on crates.io (checksum
`02d1a66277ed75f640d608235660df48c8e3c19f3b4edb6a263315626cc3c01d`), its `Cargo.toml` without the
example and test targets, and its licences. The workspace uses it through `[patch.crates-io]`.

The patch (AGP-090, review T3) is in `src/chunked/decoder.rs`, marked `xbt-rs patch`: a chunked
body whose connection ends inside a chunk is an `UnexpectedEof` error. Upstream returns `Ok(0)`
there, so a response cut short reads as a whole one and a payer takes a truncated answer as the
one it paid for. ureq gives a caller no way to see the raw body, so this cannot be checked from
outside the crate. Test: `crates/xbt402/tests/agp087_transport_http.rs::t3_a_chunked_body_cut_short_is_an_error`.

To see the patch: `diff -r <cargo registry>/ureq-2.12.1/src vendor/ureq/src`.
Drop this directory and the `[patch]` when the workspace moves to a ureq that reports it.
