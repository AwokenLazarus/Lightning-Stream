// AGP-039: the browser crypto in assets/ui.js against published vectors.
//   node crypto_test.mjs          RFC 8032 ed25519, FIPS 180 / RFC 4231 SHA-512 and HMAC, PBKDF2 (Python hashlib),
//                                 the PIN wrap round trip; exits 1 on a mismatch
//   node crypto_test.mjs emit     JSON: every signed message kind signed with a fixed seed, for
//                                 tests/crypto_js.rs to check against xbt_signer::approval and ed25519-dalek
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const require = createRequire(import.meta.url);
const W = require("../../assets/ui.js");
const { hex, unhex, utf8 } = W;

if (process.argv[2] === "emit") {
  const seed = unhex("11".repeat(32));
  const f = { token: "tok-AbC_12", dest: "http://127.0.0.1:33850", amount_sats: 150000, expiry: 1790000000, hot_address: "bcrt1qhotaddr",
              to: "bcrt1qdest", prev_sha256: "ab".repeat(32), text: "{\n  \"a\": 1\n}\n", old_pub: "cd".repeat(32), pubkey: "ef".repeat(32) };
  const out = { pub: hex(W.publicKey(seed)), cases: [] };
  for (const kind of Object.keys(W.MSG)) {
    const m = W.MSG[kind](f);
    out.cases.push({ kind, fields: f, msg: hex(m), sig: hex(W.sign(seed, m)) });
  }
  console.log(JSON.stringify(out));
  process.exit(0);
}

let fail = 0, n = 0;
function eq(name, got, want) {
  n++;
  if (got !== want) { fail++; console.log(`FAIL ${name}\n  got  ${got}\n  want ${want}`); }
}
// SHA-512 (FIPS 180-2 "abc", the empty string; lengths around the one-block padding edge from hashlib)
eq("sha512 abc", hex(W.sha512(utf8("abc"))), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
eq("sha512 empty", hex(W.sha512(new Uint8Array(0))), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
eq("sha512 a*1000", hex(W.sha512(utf8("a".repeat(1000)))), "67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634fa7b12b47d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97");
eq("sha512 x*111", hex(W.sha512(utf8("x".repeat(111)))), "9a2a120825c2319867758ec277924f6faa254968bf752046dacdd948d8ad299b10359fd04bfd7d3810b5fa1b16a294236138baff981cbb85248478053ac4d3dd");
eq("sha512 x*112", hex(W.sha512(utf8("x".repeat(112)))), "a3722b515ef40c910f2419f6e0da8ca51d410114ce6272faae64045f9e9f630e7fa8dd5a3243c9860b899d148c3da4bc0f9e07454542604d030bb55531fe0d5b");
// HMAC-SHA512 (RFC 4231 cases 1 and 2)
eq("hmac 4231.1", hex(W.hmacSha512(unhex("0b".repeat(20)), utf8("Hi There"))), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
eq("hmac 4231.2", hex(W.hmacSha512(utf8("Jefe"), utf8("what do ya want for nothing?"))), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
// PBKDF2-HMAC-SHA512 (Python hashlib.pbkdf2_hmac)
eq("pbkdf2 1", hex(W.pbkdf2(utf8("password"), utf8("salt"), 1, 64)), "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
eq("pbkdf2 4096", hex(W.pbkdf2(utf8("password"), utf8("salt"), 4096, 64)), "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");
eq("pbkdf2 100B", hex(W.pbkdf2(utf8("passwordPASSWORDpassword"), utf8("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 3, 100)), "e3ad582d92516a866ef6a2725080fbee6f7cd51734047789cccdae6581e79529601c42bf26261838b697a3a819e36dab84f1987867fc40a605429d6c540e3cb223551306ab87c412d04ce40f3def06757fe3789fdcf8e2ad8e4343427a94fe8224aa48bb");
// ed25519 (RFC 8032 section 7.1, tests 1, 2, 3)
const V = [
  ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
   "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
  ["4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
   "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"],
  ["c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
   "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"],
];
for (const [sk, pk, m, sig] of V) {
  eq("ed25519 pub " + pk.slice(0, 8), hex(W.publicKey(unhex(sk))), pk);
  eq("ed25519 sig " + pk.slice(0, 8), hex(W.sign(unhex(sk), unhex(m))), sig);
}
// the PIN wrap
const seed = unhex("42".repeat(32));
const t0 = Date.now();
const w = W.wrap(seed, "correct pin");
const ms = Date.now() - t0;
eq("unwrap", hex(W.unwrap(w, "correct pin")), hex(seed));
let refused = false;
try { W.unwrap(w, "wrong pin"); } catch (e) { refused = e.message === "wrong PIN"; }
eq("wrong pin refused", String(refused), "true");
const t1 = Date.now();
W.sign(seed, utf8("x"));
console.log(`crypto_test: ${n - fail}/${n} vectors OK; PIN wrap (${w.iter} PBKDF2 iterations) ${ms} ms, one signature ${Date.now() - t1} ms`);
process.exit(fail ? 1 : 0);
