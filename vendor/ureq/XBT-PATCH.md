# ureq 2.12.1, with one patch

This is the `src/` of ureq 2.12.1 as published on crates.io (checksum
`02d1a66277ed75f640d608235660df48c8e3c19f3b4edb6a263315626cc3c01d`), its `Cargo.toml`, and its
licences. The workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`.

## The patch

In `src/chunked/decoder.rs`, marked `xbt-rs patch` (AGP-090, review T3): a chunked body whose
connection ends inside a chunk is an `UnexpectedEof` error. Upstream returns `Ok(0)` there, so a
response cut short reads as a whole one and a payer takes a truncated answer as the one it paid
for. ureq gives a caller no way to see the raw body, so this cannot be checked from outside the
crate. Test: `crates/xbt402/tests/agp087_transport_http.rs::t3_a_chunked_body_cut_short_is_an_error`.

## Everything that differs from the published crate

- `src/chunked/decoder.rs`: the patch, nine added lines, none removed.
- `src/lib.rs`: one added constant, `pub const XBT_PATCH` (AGP-096). `xbt402`'s transport names it
  (`crates/xbt402/src/http.rs`), so a build that resolved the published ureq does not compile.
- `Cargo.toml`: the six `[[example]]` targets and the `[[test]] https-agent` target are removed
  (their files are not vendored), and a `[lints.rust]` table is added at the end
  (`unused_parens = "allow"`: upstream has one such warning, and a path dependency is not
  lint-capped as a registry one is).
- Not vendored: `Cargo.lock`, `Cargo.toml.orig`, `CHANGELOG.md`, `CONTRIBUTING.md`, `FUTURE.md`,
  `README.md`, `README.tpl`, `RELEASE.txt`, `.github/`, `examples/`, `tests/`.

To see it: `diff -r <cargo registry>/ureq-2.12.1/src vendor/ureq/src`.

## What the patch does not cover (AGP-096, the third audit's item 21)

- **Only a build whose root manifest carries the `[patch]` gets this copy.** Cargo applies
  `[patch]` from the root of a build and nowhere else. A crate outside this workspace that depends
  on `xbt402` (feature `http-client`) or on `xbt-signer`, by path or by git, resolves the published
  ureq. That used to happen with no warning. It is now a compile error in `xbt402` (`XBT_PATCH`
  not found in `ureq`), and the same error appears if `cargo update` ever takes a newer 2.12.x
  from crates.io over the patch. Such a build adds to its own root manifest:

  ```toml
  [patch.crates-io]
  ureq = { git = "<this repository>", rev = "<the rev its xbt402 is at>" }
  ```

  `scripts/cmp_clean_build.sh` step 4 builds such a consumer and carries that stanza.
- **The check covers `xbt402`'s transport, nothing else.** A crate that uses ureq itself and is
  built without the patch gets the published decoder for its own requests.
- **`cargo deny check advisories` cannot see this copy.** cargo-deny matches an advisory to a crate
  by its registry source, and a path crate has none, so the check stays green whatever is published
  against ureq 2.12.1. Advisories for ureq have to be looked up by hand
  (`ls ~/.cargo/advisory-dbs/*/crates/ureq/` after `cargo deny fetch`, or rustsec.org) whenever
  the dependency audit is run, and applied here by hand.

Drop this directory, the `[patch]` and the constant when the workspace moves to a ureq that reports
a chunked body cut short.
