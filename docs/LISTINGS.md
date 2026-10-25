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
listing from it.

## The document

JSON. `version` is `listing/0`. The fields are closed: an unknown key is not this version.

| Field | What it is |
| --- | --- |
| `name` | The seller's name, as it writes it. |
| `kind` | `video`, `files` or `api`. |
| `seller` | The seller's public origin, `http` or `https`, with no path. |
| `receipt_key` | The receipt key, hex of the 33-byte compressed public key. |
| `prices` | What a request costs, in millisatoshi, as decimal strings: `request_msat`, `byte_msat`, `per_bytes`, `second_msat`. At least one. `per_bytes` is at least 1. |
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

## An entry

```json
{
  "title": "Sintel",
  "url": "https://media.lazarus-xbt.xyz/Videos/b9937d76e453d11b407d84f188e23ed1/stream?static=true",
  "year": 2010,
  "credit": "(c) Blender Foundation, CC BY 3.0"
}
```
