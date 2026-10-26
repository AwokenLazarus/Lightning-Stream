# Listings: a seller's catalog, `listing/0`

A listing is how a buyer finds what a seller sells without asking anyone else. The seller
serves it, free, at `GET /.well-known/lightning-stream.json` on the same origin its 402 terms
name. `/services` stays the unsigned machine list (`docs/TICKETS.md`, section 8). This document
is the catalog a person reads, and it is signed.

The signature is the receipt key's: the same ECDSA key the 402 terms name in
`accepts[0].extra.receiptKey`, the key that signs receipts. A reader checks two things and
keeps the document only when both hold. The signature verifies under `receipt_key` in the
document, and that key is the one the terms of the seller's URL name. A document that names a
different key, or a different origin, is not that seller's catalog.

No directory and no relay is part of this. A buyer who already has a seller's URL fetches the
listing from it. To read the terms, the buyer asks that URL; when it is not a priced path (a seller
whose `/` is no route answers 404), it asks the paths the listing sells under, all on the same
origin. A seller can also publish the same signed document on Nostr, so that buyers who do not
have its URL can find it (`docs/NOSTR.md`).

There are two versions. `listing/0` describes one service. `listing/1` lists several, each sold
under a route of its own (a media server at `/`, a model's API at `/ai/`); it is described after
the first.

## The document

JSON. `version` is `listing/0`. The fields are closed: an unknown key is not this version.

| Field | What it is |
| --- | --- |
| `name` | The seller's name, as it writes it. |
| `kind` | `video`, `files`, `api`, `ai` (a model asked over HTTP, such as a local language model) or `hashrate` (pieces of mining work, rented as in [P2P-HASH.md](P2P-HASH.md)). |
| `seller` | The seller's public origin, `http` or `https`, with no path. |
| `receipt_key` | The receipt key, hex of the 33-byte compressed public key. |
| `prices` | What a request costs, in millisatoshi, as decimal strings: `request_msat`, `byte_msat`, `per_bytes`, `second_msat`, and for a model priced by the token `per_1k_input_msat` and `per_1k_output_msat` (per 1,000 tokens; shown as "10 sat per 1,000 tokens", or "2 sat per 1,000 tokens in, 10 sat per 1,000 tokens out" when input is priced too). At least one. `per_bytes` is at least 1. A reader older than the token prices refuses a listing that names them. |
| `items` | The catalog. Each entry has `title` and `url` (`http` or `https`). `year` and `credit` are optional; `year` is a number. |
| `licence` | The terms the works are offered under. |
| `credits` | Who made them. |
| `updated` | When the seller last changed the catalog, as it writes the date. |
| `sig` | Hex of the DER signature. |

`seller` and `receipt_key` are the gateway's, not a line of the config. The config's `listing`
section is `name`, `kind`, `prices`, `items`, `licence`, `credits` and `updated`. Prices in the
config are whole numbers; the document writes them as decimal strings, as the rest of the wire
writes amounts. Absent section, or `null`: the URL answers 404.

## What is signed

`sig` is removed. What remains is written as `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
The digest is one tagged hash, the same construction as a request digest: tag
`xbt402/listing/0`, then one length-prefixed field of those bytes. The receipt key signs that
32-byte digest. Key order and spaces in the served JSON do not change the digest, because a
reader parses and writes the canonical form again before it checks.

## `listing/1`: several services

A gateway can sell several services, each behind a route with its own upstream and price. Its
listing is then `listing/1`. The fields are closed here too:

| Field | What it is |
| --- | --- |
| `version` | `listing/1`. |
| `name` | The seller's name. |
| `seller`, `receipt_key`, `updated`, `sig` | As in `listing/0`. |
| `licence`, `credits` | Optional: what holds for every service that does not say its own. |
| `services` | One to 32 entries, each `name`, `kind` (`video`, `files`, `api`, `ai` or `hashrate`), `path`, `prices` and `items`, with an optional `licence` and `credits`. `path` is the gateway route the service is sold under; no two entries share one. |

New kinds come after the apps that read them. A reader skips a `listing/1` service whose `kind`
it does not know, and reads the rest: the signature still covers the whole document, the skipped
service included, so nothing in it can be changed unseen. A service of a kind the reader knows is
checked whole, as before. A listing with no service of a kind the reader knows is refused. A
`listing/0` has one service, so its `kind` stays strict: with it unknown there is nothing to read.
A seller's own config is strict too: it can list only the kinds its gateway knows.

The kinds `ai` and `hashrate` came before this rule: apps older than it refuse a listing with such
a service. A seller who must reach those apps lists a model as `api`.

The digest is built as for `listing/0`, under its own tag, `xbt402/listing/1`, so a document of one
version cannot be passed off as the other.

In the config, the `listing` section with a `services` list is a `listing/1` draft. Each service
names a route that exists. A service that leaves out `prices` is given its route's price, which
is how the page that writes the config keeps the two from disagreeing:

```json
"listing": {
  "name": "One box",
  "updated": "2026-10-26",
  "services": [
    {"name": "Films", "kind": "video", "path": "/", "items": [{"title": "Sintel", "url": "https://seller.example/Videos/s"}]},
    {"name": "Local model", "kind": "ai", "path": "/ai/", "items": []}
  ]
}
```

A reader sees a `listing/0` as one service under `/`.

## An entry

```json
{
  "title": "Sintel",
  "url": "https://media.lazarus-xbt.xyz/Videos/b9937d76e453d11b407d84f188e23ed1/stream?static=true",
  "year": 2010,
  "credit": "(c) Blender Foundation, CC BY 3.0"
}
```
