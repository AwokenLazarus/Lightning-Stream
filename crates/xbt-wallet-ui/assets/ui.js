// xbt-wallet-ui (AGP-039, AGP-041): the human's ed25519 key lives in this browser, never on the box.
// Pure JavaScript: WebCrypto is only there in a secure context, and a box is often plain http on the
// LAN or an .onion. SHA-512, HMAC, PBKDF2 and ed25519 (RFC 8032) below; tests/js/crypto_test.mjs
// checks them against RFC 8032 and RFC 4231 vectors and against the signer (ed25519-dalek).
// AGP-041: wrap the seed under a passphrase (≥12, not all-digit, not a repeated pattern) with
// PBKDF2-SHA512 at 210,000 iterations (OWASP). A 60k wrap unlocks once and is re-wrapped.
"use strict";
(function (root) {
  // ---- bytes ------------------------------------------------------------------------------------
  function hex(b) { var s = ""; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16); return s; }
  function unhex(s) {
    s = String(s).trim().toLowerCase();
    if (s.length % 2 || /[^0-9a-f]/.test(s)) throw new Error("not hex");
    var b = new Uint8Array(s.length / 2);
    for (var i = 0; i < b.length; i++) b[i] = parseInt(s.substr(2 * i, 2), 16);
    return b;
  }
  function utf8(s) { return new TextEncoder().encode(s); }
  function concat() {
    var n = 0, i, o = 0;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var out = new Uint8Array(n);
    for (i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; }
    return out;
  }
  function randomBytes(n) { var b = new Uint8Array(n); root.crypto.getRandomValues(b); return b; }

  // ---- SHA-512 (FIPS 180-4), 32-bit halves --------------------------------------------------------
  var K = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538,
    0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
    0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, 0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
    0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5, 0x983e5152, 0xee66dfab,
    0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed,
    0x53380d13, 0x9d95b3df, 0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
    0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8, 0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
    0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373,
    0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c,
    0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
    0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b, 0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
    0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817];
  var IV = [0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179];

  function compress(H, W, blk, off) {
    var i, j;
    for (i = 0; i < 32; i++) W[i] = (blk[off + 4 * i] << 24 | blk[off + 4 * i + 1] << 16 | blk[off + 4 * i + 2] << 8 | blk[off + 4 * i + 3]) >>> 0;
    for (i = 32; i < 160; i += 2) {
      var xh = W[i - 30], xl = W[i - 29];
      var s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      var s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      xh = W[i - 4]; xl = W[i - 3];
      var s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      var s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
      var lo = (s0l >>> 0) + (s1l >>> 0) + W[i - 13] + W[i - 31];
      var hi = s0h + s1h + W[i - 14] + W[i - 32] + Math.floor(lo / 4294967296);
      W[i] = hi >>> 0; W[i + 1] = lo >>> 0;
    }
    var ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
    var eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
    for (j = 0; j < 160; j += 2) {
      var S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
      var S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
      var chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
      var t1l = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + K[j + 1] + W[j + 1];
      var t1h = hh + S1h + chh + K[j] + W[j] + Math.floor(t1l / 4294967296);
      t1l = t1l >>> 0; t1h = t1h >>> 0;
      var S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
      var S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
      var mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
      var t2l = (S0l >>> 0) + (mjl >>> 0);
      var t2h = S0h + mjh + Math.floor(t2l / 4294967296);
      t2l = t2l >>> 0;
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      var nel = (dl >>> 0) + t1l;
      eh = (dh + t1h + Math.floor(nel / 4294967296)) >>> 0; el = nel >>> 0;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
      var nal = t1l + t2l;
      ah = (t1h + t2h + Math.floor(nal / 4294967296)) >>> 0; al = nal >>> 0;
    }
    var v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
    for (i = 0; i < 16; i += 2) {
      var l = (H[i + 1] >>> 0) + (v[i + 1] >>> 0);
      H[i] = (H[i] + v[i] + Math.floor(l / 4294967296)) >>> 0; H[i + 1] = l >>> 0;
    }
  }

  function sha512(msg) {
    var len = msg.length, padLen = ((len + 17 + 127) >> 7) << 7;
    var blk = new Uint8Array(padLen);
    blk.set(msg); blk[len] = 0x80;
    var bits = len * 8;
    for (var i = 0; i < 8 && bits > 0; i++) { blk[padLen - 1 - i] = bits % 256; bits = Math.floor(bits / 256); }
    var H = IV.slice(), W = new Array(160);
    for (var off = 0; off < padLen; off += 128) compress(H, W, blk, off);
    var out = new Uint8Array(64);
    for (i = 0; i < 16; i++) { out[4 * i] = H[i] >>> 24; out[4 * i + 1] = H[i] >>> 16 & 255; out[4 * i + 2] = H[i] >>> 8 & 255; out[4 * i + 3] = H[i] & 255; }
    return out;
  }

  function hmacSha512(key, msg) {
    if (key.length > 128) key = sha512(key);
    var k = new Uint8Array(128); k.set(key);
    var ip = new Uint8Array(128), op = new Uint8Array(128);
    for (var i = 0; i < 128; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    return sha512(concat(op, sha512(concat(ip, msg))));
  }

  // PBKDF2-HMAC-SHA512 (RFC 8018), dkLen <= 64 bytes per block, any number of blocks.
  function pbkdf2(password, salt, iter, dkLen) {
    var out = new Uint8Array(dkLen), blocks = Math.ceil(dkLen / 64);
    for (var b = 1; b <= blocks; b++) {
      var u = hmacSha512(password, concat(salt, new Uint8Array([b >>> 24, b >>> 16 & 255, b >>> 8 & 255, b & 255])));
      var t = u.slice();
      for (var i = 1; i < iter; i++) { u = hmacSha512(password, u); for (var j = 0; j < 64; j++) t[j] ^= u[j]; }
      out.set(t.subarray(0, Math.min(64, dkLen - (b - 1) * 64)), (b - 1) * 64);
    }
    return out;
  }

  // ---- ed25519 (RFC 8032), BigInt --------------------------------------------------------------
  var P = (1n << 255n) - 19n;
  var L = (1n << 252n) + 27742317777372353535851937790883648493n;
  function mod(a, m) { var r = a % (m || P); return r >= 0n ? r : r + (m || P); }
  function pow(b, e) { var r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
  function inv(a) { return pow(a, P - 2n); }
  var D = mod(-121665n * inv(121666n));
  var D2 = mod(2n * D);
  var BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  var BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
  var BASE = [BX, BY, 1n, mod(BX * BY)];
  function add(p, q) {
    var a = mod((p[1] - p[0]) * (q[1] - q[0])), b = mod((p[1] + p[0]) * (q[1] + q[0]));
    var c = mod(p[3] * D2 * q[3]), d = mod(p[2] * 2n * q[2]);
    var e = b - a, f = d - c, g = d + c, h = b + a;
    return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  }
  function mul(s, p) {
    var q = [0n, 1n, 1n, 0n];
    while (s > 0n) { if (s & 1n) q = add(q, p); p = add(p, p); s >>= 1n; }
    return q;
  }
  function encode(p) {
    var zi = inv(p[2]), x = mod(p[0] * zi), y = mod(p[1] * zi);
    var out = new Uint8Array(32);
    for (var i = 0; i < 32; i++) { out[i] = Number(y & 255n); y >>= 8n; }
    if (x & 1n) out[31] |= 0x80;
    return out;
  }
  function le(b) { var r = 0n; for (var i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]); return r; }
  function leBytes(n, len) { var out = new Uint8Array(len); for (var i = 0; i < len; i++) { out[i] = Number(n & 255n); n >>= 8n; } return out; }
  function expand(seed) {
    if (seed.length !== 32) throw new Error("an ed25519 seed is 32 bytes");
    var h = sha512(seed), a = h.slice(0, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    return { a: le(a), prefix: h.slice(32) };
  }
  function publicKey(seed) { return encode(mul(expand(seed).a, BASE)); }
  function sign(seed, msg) {
    var e = expand(seed), A = encode(mul(e.a, BASE));
    var r = mod(le(sha512(concat(e.prefix, msg))), L);
    var R = encode(mul(r, BASE));
    var k = mod(le(sha512(concat(R, A, msg))), L);
    return concat(R, leBytes(mod(r + k * e.a, L), 32));
  }

  // ---- the signed messages (xbt_signer::approval) -----------------------------------------------
  function joinLines(parts) { return utf8(parts.join("\n")); }
  var MSG = {
    approve: function (f) { return joinLines(["xbt-agentwallet-approve-v1", f.token, f.dest, String(f.amount_sats), String(f.expiry)]); },
    sweep: function (f) { return joinLines(["xbt-agentwallet-hot-sweep-v1", f.hot_address, f.to, String(f.amount_sats), String(f.expiry)]); },
    policy: function (f) { return joinLines(["xbt-agentwallet-policy-v1", f.prev_sha256, String(f.expiry), f.text]); },
    "human-key": function (f) { return joinLines(["xbt-agentwallet-human-key-v1", f.old_pub, f.pubkey, String(f.expiry)]); },
    rotate: function (f) { return joinLines(["xbt-agentwallet-hot-rotate-v1", f.hot_address, String(f.expiry)]); },
    backup: function (f) { return joinLines(["xbt-agentwallet-backup-v1", f.hot_address, String(f.expiry)]); },
    deny: function (f) { return joinLines(["xbt-agentwallet-deny-v1", f.token, String(f.expiry)]); },
    unblock: function (f) { return joinLines(["xbt-agentwallet-unblock-v1", f.block, String(f.expiry)]); }
  };

  // ---- the key in this browser: the seed XORed with a PBKDF2 pad of the passphrase, and a MAC ------
  // ITER is OWASP 2023+ for PBKDF2-HMAC-SHA512. LEGACY_ITER is AGP-039's wrap; unlock once, then re-wrap.
  var STORE = "xbt-wallet-human-key-v1", PENDING = "xbt-wallet-human-key-pending-v1";
  var ITER = 210000, LEGACY_ITER = 60000;
  function storage() { try { return root.localStorage; } catch (e) { return null; } }
  function isRepeatedPattern(pw) {
    var n = pw.length, i, block, k;
    if (n < 2) return false;
    if (/^(.)\1+$/.test(pw)) return true;
    for (i = 1; i <= Math.floor(n / 2); i++) {
      if (n % i) continue;
      block = pw.slice(0, i);
      for (k = i; k < n; k += i) if (pw.slice(k, k + i) !== block) break;
      if (k >= n) return true;
    }
    return false;
  }
  function passphraseStrength(pw) {
    pw = String(pw || "");
    var digits = pw.replace(/\s+/g, "");
    var classes = (/[a-z]/.test(pw) ? 1 : 0) + (/[A-Z]/.test(pw) ? 1 : 0) + (/[0-9]/.test(pw) ? 1 : 0) + (/[^A-Za-z0-9\s]/.test(pw) ? 1 : 0);
    var reason = "", score = 0, hint;
    if (pw.length < 12) reason = "the passphrase needs at least 12 characters";
    else if (/^\d+$/.test(digits)) reason = "the passphrase cannot be only digits";
    else if (isRepeatedPattern(pw)) reason = "the passphrase cannot be a repeated pattern";
    else {
      score = 1;
      if (pw.length >= 12 && classes >= 2) score = 2;
      if (pw.length >= 16 && classes >= 3) score = 3;
    }
    hint = score === 0 ? reason : score === 1 ? "weak — add length or mixed characters" : score === 2 ? "fair" : "strong";
    return { ok: score > 0, score: score, hint: hint, reason: reason };
  }
  function wrap(seed, pin, iter) {
    var n = iter || ITER, salt = randomBytes(16), dk = pbkdf2(utf8(pin), salt, n, 64);
    var ct = new Uint8Array(32);
    for (var i = 0; i < 32; i++) ct[i] = seed[i] ^ dk[i];
    return { v: 1, kdf: "pbkdf2-sha512", iter: n, salt: hex(salt), ct: hex(ct),
             mac: hex(hmacSha512(dk.subarray(32), ct).subarray(0, 16)), pub: hex(publicKey(seed)) };
  }
  function unwrap(w, pin) {
    var dk = pbkdf2(utf8(pin), unhex(w.salt), w.iter, 64), ct = unhex(w.ct);
    if (hex(hmacSha512(dk.subarray(32), ct).subarray(0, 16)) !== w.mac) throw new Error("wrong passphrase");
    var seed = new Uint8Array(32);
    for (var i = 0; i < 32; i++) seed[i] = ct[i] ^ dk[i];
    if (hex(publicKey(seed)) !== w.pub) throw new Error("the stored key is damaged");
    return seed;
  }
  function needsMigrate(w) {
    return !!(w && w.kdf === "pbkdf2-sha512" && ((w.iter | 0) < ITER));
  }
  function unlock(w, pin) {
    var seed = unwrap(w, pin), migrated = false, stored = w;
    if (needsMigrate(w)) {
      stored = wrap(seed, pin, ITER);
      try { saveKey(stored); } catch (e) { /* node / no localStorage: the caller keeps `wrapped` */ }
      migrated = true;
    }
    return { seed: seed, wrapped: stored, migrated: migrated };
  }
  function loadKey(slot) { var s = storage(); try { return s ? JSON.parse(s.getItem(slot || STORE) || "null") : null; } catch (e) { return null; } }
  function saveKey(w, slot) { var s = storage(); if (!s) throw new Error("this browser keeps no local storage"); s.setItem(slot || STORE, JSON.stringify(w)); }
  function dropKey(slot) { var s = storage(); if (s) s.removeItem(slot || STORE); }

  var api = { hex: hex, unhex: unhex, utf8: utf8, sha512: sha512, hmacSha512: hmacSha512, pbkdf2: pbkdf2, publicKey: publicKey,
              sign: sign, MSG: MSG, wrap: wrap, unwrap: unwrap, unlock: unlock, needsMigrate: needsMigrate,
              passphraseStrength: passphraseStrength, loadKey: loadKey, saveKey: saveKey, dropKey: dropKey,
              STORE: STORE, PENDING: PENDING, ITER: ITER, LEGACY_ITER: LEGACY_ITER };
  root.XbtWallet = api;
  if (typeof module !== "undefined") module.exports = api;

  // ---- the page -----------------------------------------------------------------------------------
  if (typeof document === "undefined") return;

  function $(sel, el) { return (el || document).querySelector(sel); }
  function $$(sel, el) { return Array.prototype.slice.call((el || document).querySelectorAll(sel)); }
  function say(el, text, bad) {
    if (!el) return;
    el.textContent = text;
    el.classList.remove("ok", "bad");
    el.classList.add("msg", bad ? "bad" : "ok");
  }
  function fields(form) {
    var f = {};
    $$("input,textarea,select", form).forEach(function (i) { if (i.name) f[i.name] = i.value; });
    return f;
  }

  // Signed forms: the message is rebuilt here from the fields shown, never taken from the server.
  $$("form[data-sign]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      var out = $(".sign-msg", form);
      var ext = $("[name=signature_ext]", form);
      if (ext && ext.value.trim()) return; // signed on another device
      ev.preventDefault();
      var kind = form.getAttribute("data-sign"), f = fields(form);
      var shown = $("pre.signed-text", form);
      if (kind === "policy" && shown && shown.textContent !== f.text) { say(out, "the text shown differs from the text to sign: refused", true); return; }
      var w = loadKey();
      if (!w) { say(out, "this browser holds no approval key: make one under Settings, Keys and backup, or sign on another device and paste the signature", true); return; }
      var enrolled = form.getAttribute("data-human");
      if (enrolled && enrolled !== w.pub) { say(out, "the key in this browser is not your enrolled approval key", true); return; }
      var pinEl = $("input.pin", form);
      var pin = pinEl ? pinEl.value : "";
      if (!pin) { say(out, "enter your passphrase", true); return; }
      say(out, "signing…");
      setTimeout(function () {
        try {
          var unlocked = unlock(w, pin);
          var seed = unlocked.seed;
          if (kind === "human-key") {
            // the new key is made here and kept aside until the signer answers
            var fresh = randomBytes(32);
            f.pubkey = hex(publicKey(fresh));
            $("[name=pubkey]", form).value = f.pubkey;
            saveKey(wrap(fresh, pin), PENDING);
          }
          var sig = sign(seed, MSG[kind](f));
          seed.fill(0);
          $("[name=signature]", form).value = hex(sig);
          if (pinEl) pinEl.value = "";
          form.submit();
        } catch (e) {
          if (e.message !== "wrong passphrase") { say(out, e.message, true); return; }
          // the passphrase is the one chosen when the key was made; the backup file is the key itself
          say(out, "Wrong passphrase. Forgot it? ", true);
          var a = document.createElement("a");
          a.href = "./keys#restore";
          a.textContent = "Restore the key from its backup file and choose a new passphrase";
          out.appendChild(a);
          out.appendChild(document.createTextNode("."));
        }
      }, 20);
    });
  });

  // ./keys#restore: the restore from a backup, opened
  if (root.location && root.location.hash === "#restore") {
    var rs = $("#restore");
    if (rs) { $$("details", rs).concat([rs]).forEach(function (d) { if (d.tagName === "DETAILS") d.open = true; }); rs.scrollIntoView(); }
  }
  // ./sell#capacity: a service's "How many buyers at once", opened (on load, and when a link on the
  // page itself leads there)
  function openCapacity() {
    if (!root.location || root.location.hash !== "#capacity") return;
    var cp = $("#capacity");
    if (cp) { cp.open = true; cp.scrollIntoView(); }
  }
  openCapacity();
  if (root.addEventListener) root.addEventListener("hashchange", openCapacity);

  // The Sell form's "Publish without buyer accounts anyway": shown only where its warning applies, as the save
  // checks it: a media server's web app (Media, or Jellyfin, Emby or Plex by its name or address) with neither
  // buyers' own accounts nor a guest login
  $$("[data-no-accounts]").forEach(function (box) {
    var form = box.closest("form");
    if (!form) return;
    function field(n) { return form.querySelector("[name='" + n + "']"); }
    function update() {
      var k = form.querySelector("[name='kind']:checked"), kind = k ? k.value : "media";
      var app = field("app"), acc = field("app_accounts"), login = field("app_login"), name = field("name"), addr = field("address");
      var media = kind === "media" || /jellyfin|emby|plex/i.test((name ? name.value : "") + " " + (addr ? addr.value : ""));
      var appOn = kind !== "files" && (kind === "media" || !!(app && app.checked));
      box.hidden = !(appOn && media && !(acc && acc.checked) && !(login && login.value.trim()));
    }
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  });

  // A rotation of the human key finished: promote the pending key.
  var hk = $("#human-key-state");
  if (hk) {
    var enrolled = hk.getAttribute("data-enrolled"), mine = loadKey(), pend = loadKey(PENDING);
    if (pend && pend.pub === enrolled) { saveKey(pend); dropKey(PENDING); mine = pend; }
    else if (pend && mine && mine.pub === enrolled) { dropKey(PENDING); }
    var st = $("#browser-key");
    if (st) {
      if (!mine && enrolled) {
        // a hint, not an error: the key is enrolled and lives in another browser (0.2.5 said it in red)
        st.textContent = "This browser can't sign approvals: your approval key is in the browser you made it in. Sign there, " +
          "or use \u201cSign on another device\u201d under an approval. To sign here, put the key in this browser from its backup.";
        st.classList.remove("ok", "bad");
        st.classList.add("msg", "hint");
      }
      else if (!mine) say(st, "This browser holds no approval key yet.", true);
      else if (!enrolled) say(st, "This browser holds a key (" + mine.pub.slice(0, 16) + "…), not enrolled yet.", true);
      else if (mine.pub === enrolled) say(st, "This browser holds the enrolled approval key (" + mine.pub.slice(0, 16) + "…).");
      else say(st, "This browser holds another key (" + mine.pub.slice(0, 16) + "…), not the enrolled one.", true);
    }
  }

  // Key setup: generate, show the backup, confirm it, protect it with a passphrase, enrol the public key.
  var gen = $("#keygen");
  if (gen) {
    var seed = null;
    function paintStrength(pw) {
      var el = $("#keygen-strength");
      if (!el) return;
      var s = passphraseStrength(pw);
      el.textContent = s.ok ? ("Strength: " + s.hint) : (pw ? s.reason : "At least 12 characters, not only digits, not a repeated pattern.");
      el.className = "hint" + (pw ? (s.ok ? (s.score >= 3 ? " ok" : " warn") : " bad") : "");
    }
    $("#keygen-new").addEventListener("click", function () {
      seed = randomBytes(32);
      $("#keygen-backup").textContent = hex(seed);
      $("#keygen-step2").hidden = false;
      paintStrength($("#keygen-pin").value);
    });
    $("#keygen-import").addEventListener("click", function () {
      try { seed = unhex($("#keygen-import-hex").value); if (seed.length !== 32) throw new Error("the key is 64 hex characters"); }
      catch (e) { say($("#keygen-msg"), e.message, true); return; }
      $("#keygen-backup").textContent = hex(seed);
      $("#keygen-step2").hidden = false;
      paintStrength($("#keygen-pin").value);
    });
    $("#keygen-pin").addEventListener("input", function () { paintStrength(this.value); });
    var downloaded = false;
    var dl = $("#keygen-download");
    if (dl) dl.addEventListener("click", function () {
      if (!seed) return;
      var text = "Lightning Stream: approval key backup (this is not your passphrase)\n\n" + hex(seed) + "\n\nThis is the only copy of your approval key. Keep it offline and private: " +
                 "whoever has it can approve payments and change your spending rules. To restore it, open Keys, then " +
                 "\"restore a key from its backup\", paste the 64 characters above and choose a passphrase.\n\n" +
                 "Your passphrase is not in this file. It is what you typed when you made the key, and it unlocks the key in your browser. " +
                 "Forgot it? Restore the key from this file and choose a new one.\n";
      var a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      a.download = "lightning-stream-approval-key-backup.txt";
      document.body.appendChild(a); a.click(); a.remove();
      downloaded = true;
      var box = $("#keygen-saved"); if (box) { box.disabled = false; box.checked = true; }
    });
    $("#keygen-save").addEventListener("click", function () {
      var msg = $("#keygen-msg");
      if (!seed) { say(msg, "generate or import a key first", true); return; }
      var tail = hex(seed).slice(-8);
      var savedBox = $("#keygen-saved");
      var typed = $("#keygen-confirm").value.trim().toLowerCase() === tail;
      // the backup was downloaded and the owner says it is kept, or its end was typed back
      if (!typed && !(downloaded && savedBox && savedBox.checked)) {
        say(msg, downloaded ? "tick \"I saved the backup somewhere safe\" once it is kept" : "download the backup file (or type its last 8 characters) first", true);
        return;
      }
      var p1 = $("#keygen-pin").value, p2 = $("#keygen-pin2").value;
      var strength = passphraseStrength(p1);
      if (!strength.ok) { say(msg, strength.reason, true); paintStrength(p1); return; }
      if (p1 !== p2) { say(msg, "the passphrases differ", true); return; }
      say(msg, "protecting the key…");
      setTimeout(function () {
        try {
          saveKey(wrap(seed, p1));
          var pub = hex(publicKey(seed));
          seed.fill(0); seed = null;
          $("#keygen-backup").textContent = "(saved; this page no longer shows it)";
          var f = $("#enroll-form");
          if (f) {
            $("[name=pubkey]", f).value = pub;
            var code = $("[name=code]", f);
            // the box gave the enrolment code: one step, nothing more to do here
            if (code && code.type === "hidden" && code.value) { say(msg, "Saved in this browser. Setting it up…"); f.submit(); }
            else { f.hidden = false; say(msg, "Saved in this browser. Public key " + pub + ". Enroll it below."); }
          }
          else say(msg, "Saved in this browser. Public key " + pub + ".");
        } catch (e) { say(msg, e.message, true); }
      }, 20);
    });
    var forget = $("#keygen-forget");
    if (forget) forget.addEventListener("click", function () { dropKey(); dropKey(PENDING); say($("#keygen-msg"), "Removed from this browser."); });
  }

  // A seller's own app: its frame opens on the app port (another origin than this page), with the
  // one-time code the port trades for its cookie; what the visit has spent is asked every 2 s, and the
  // frame is closed when the visit ends (stopped, or its limit reached).
  $$(".app-visit[data-visit]").forEach(function (box) {
    var frame = $("iframe.seller-app", box), spent = $("[data-visit-spent]", box), state = $("[data-visit-state]", box), note = $("[data-visit-note]", box);
    var paid = $("[data-visit-paid]", box), refusal = $("[data-visit-refusal]", box), shown = "";
    // the visit's limit as it stands, and the owner's button to add to it once most of it is used (never by itself)
    var limitEl = $("[data-visit-limit]", box), add = $("[data-visit-add]", box), csrf = $("input[name='csrf']", box);
    var visit = box.getAttribute("data-visit"), port = box.getAttribute("data-port"), code = box.getAttribute("data-code");
    if (!frame || !/^[0-9a-f]+$/.test(visit || "") || !/^[0-9]+$/.test(port || "") || !/^[0-9a-f]+$/.test(code || "")) return;
    // the frame keeps the page's own background until the app has loaded: no white flash in dark mode
    frame.addEventListener("load", function () { frame.classList.add("loaded"); });
    frame.src = location.protocol + "//" + location.hostname + ":" + port + "/__ls/enter?c=" + code;
    box.removeAttribute("data-code");
    var timer = null;
    function ended(words) {
      if (timer) clearInterval(timer);
      timer = null;
      if (state) { state.textContent = "Ended"; state.className = "pill warn"; }
      if (note) note.textContent = words + " Open the app again from its service's page to go on.";
      frame.removeAttribute("src");
      frame.hidden = true;
    }
    // the wallet's refusal of a request of the visit, in words, with the links to its fix
    function showRefusal(r) {
      var key = r ? JSON.stringify(r) : "";
      if (key === shown) return;
      shown = key;
      while (refusal.firstChild) refusal.removeChild(refusal.firstChild);
      refusal.hidden = !r;
      if (!r) return;
      function add(tag, text, parent) { var el = document.createElement(tag); if (text) el.textContent = text; (parent || refusal).appendChild(el); return el; }
      add("h3", String(r.title || "Not paid"));
      add("p", String(r.words || ""));
      if (r.fix) add("p", String(r.fix));
      var row = null;
      (Array.isArray(r.links) ? r.links : []).forEach(function (l) {
        var to = String(l[0] || "");
        if (!/^\.\/[a-z-]+$/.test(to) && to.indexOf("https://lightning-stream.com/") !== 0) return;
        if (!row) { row = add("p"); row.className = "row"; }
        var a = add("a", String(l[1] || to), row);
        a.className = "button-link";
        a.href = to;
        if (to.indexOf("https://") === 0) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
      });
      if (r.details) {
        var d = add("details");
        add("summary", "Details", d);
        var p = add("p", "", d);
        p.className = "small";
        add("code", String(r.details), p);
      }
    }
    if (add && csrf) {
      add.addEventListener("click", function () {
        add.disabled = true;
        var body = new URLSearchParams();
        body.set("csrf", csrf.value);
        body.set("visit", visit);
        body.set("add", add.getAttribute("data-visit-add") || "0");
        fetch("./app-limit", { method: "POST", credentials: "same-origin", body: body }).then(function () { add.disabled = false; ask(); })
          .catch(function () { add.disabled = false; });
      });
    }
    // the credit is the signer's with the shop: every visit, AI call and player link using that shop draws on it
    var sharedNote = " (shared with your other uses of this shop)";
    function ask() {
      fetch("./api/visit?v=" + visit, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (v) {
        if (spent && typeof v.spent_sats === "number") spent.textContent = v.spent_sats.toLocaleString();
        if (limitEl && typeof v.limit_sats === "number") limitEl.textContent = v.limit_sats.toLocaleString();
        // Add shows once 80% of the limit is used, or at the limit: never at the start of a visit. What was used, not what
        // was paid ahead (an older connector's spent_sats counts the first ticket, most of a small limit)
        var used = typeof v.used_sats === "number" ? v.used_sats : v.spent_sats;
        var near = typeof used === "number" && typeof v.limit_sats === "number" && v.limit_sats > 0 && used > 0 && used >= 0.8 * v.limit_sats;
        if (add) add.hidden = v.ended && !v.limit_reached ? true : !(near || v.limit_reached === true);
        if (state) {
          if (v.limit_reached) { state.textContent = "Limit reached"; state.className = "pill warn"; }
          else if (!v.ended) { state.textContent = "Open"; state.className = "pill good"; }
        }
        // at its limit the visit waits for the owner: the page stays as it is, and Add lets it go on
        if (v.limit_reached) return;
        if (paid) paid.textContent = typeof v.prepaid_sats === "number" && v.prepaid_sats > 0
          ? " · paid " + v.prepaid_sats.toLocaleString() + " sat"
            + (typeof v.tickets_bought === "number" && v.tickets_bought > 0 ? " for " + v.tickets_bought + (v.tickets_bought === 1 ? " ticket" : " tickets") : "")
            + (typeof v.credit_sats === "number" ? " · credit left with the shop: " + v.credit_sats.toLocaleString() + " sat" + sharedNote : "")
          : typeof v.credit_left_sats === "number" ? " · credit with the shop: " + v.credit_left_sats.toLocaleString() + " sat" + sharedNote : "";
        if (refusal) showRefusal(v.refusal);
        if (v.ended) ended(String(v.ended));
      }).catch(function () {});
    }
    timer = setInterval(ask, 2000);
    ask();
  });

  // A service found on this box fills the address field in one click (the Sell page).
  $$("[data-fill]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var form = btn.closest("form"), field = form && form.querySelector("[name='" + btn.getAttribute("data-fill") + "']");
      if (field) { field.value = btn.getAttribute("data-value"); field.focus(); }
    });
  });

  // Copy buttons: the Connected apps page's connection string, shown once. The clipboard API needs a
  // secure context; on plain http (a box on the LAN) the field is selected and copied the old way.
  $$("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.getAttribute("data-copy"));
      if (!el) return;
      var done = function () { btn.textContent = "Copied"; };
      var old = function () { el.focus(); el.select(); try { if (document.execCommand("copy")) done(); } catch (e) { /* selected: copy by hand */ } };
      if (root.isSecureContext && root.navigator && root.navigator.clipboard) root.navigator.clipboard.writeText(el.value).then(done, old);
      else old();
    });
  });

  // The menu: on a phone, one button opens it.
  var doc = root.document;
  if (doc && doc.documentElement) {
    doc.documentElement.classList.add("js");
    var toggle = $(".menu-toggle"), header = $("header");
    // the bar casts a shadow once the page has scrolled under it
    if (header) {
      var edge = function () { header.classList.toggle("scrolled", (root.scrollY || 0) > 4); };
      root.addEventListener("scroll", edge, { passive: true }); edge();
    }
    if (toggle && header) {
      toggle.addEventListener("click", function () {
        var open = header.classList.toggle("open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }
    // The theme: dark by default, light when the owner picks it here; kept in this browser
    // (vt.js applies it before the next page's first paint).
    var theme = $(".theme-toggle"), html = doc.documentElement;
    if (theme) {
      var show = function () {
        var light = html.getAttribute("data-theme") === "light";
        theme.setAttribute("aria-pressed", light ? "true" : "false");
      };
      show();
      theme.addEventListener("click", function () {
        var light = html.getAttribute("data-theme") !== "light";
        if (light) html.setAttribute("data-theme", "light"); else html.removeAttribute("data-theme");
        try { root.localStorage.setItem("ls-theme", light ? "light" : "dark"); } catch (e) { /* no storage: this page only */ }
        show();
      });
    }
  }

  // Live connections: when money moved since the last look, a pulse runs down the river.
  var spent = $$("[data-spent]");
  if (spent.length) {
    var now = 0, before = null;
    spent.forEach(function (el) { now += Number(el.getAttribute("data-spent")) || 0; });
    try { before = Number(root.sessionStorage.getItem("ls-spent")); root.sessionStorage.setItem("ls-spent", String(now)); } catch (e) { /* no storage */ }
    if (before !== null && now > before) {
      root.addEventListener("load", function () { if (root.lsRiver) root.lsRiver.pulse(); });
    }
  }

  // Buy → Hashrate: the rentals, shown again every 5 s while one is live (money spent, pieces paid, its state), and no
  // more once none is. Not while the owner is in one of their forms (a Cut on its way).
  var rentals = $("#rentals[data-live]");
  if (rentals && root.fetch) {
    var rentalsTimer = setInterval(function () {
      root.fetch("./api/hashrate-rentals", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || typeof d.html !== "string" || rentals.contains(document.activeElement)) return;
          rentals.innerHTML = d.html;
          if (!d.live) { rentals.removeAttribute("data-live"); clearInterval(rentalsTimer); }
        })
        .catch(function () {});
    }, 5000);
  }

  // Buy → Hashrate while the renter is still looking for offers on Nostr: the page is loaded again in a few seconds,
  // and not while the owner is in one of its forms.
  var again = $("[data-reload-after]");
  if (again) {
    var reloadSoon = function () {
      var a = document.activeElement;
      if (a && a.form) { setTimeout(reloadSoon, 3000); return; }
      root.location.reload();
    };
    setTimeout(reloadSoon, (Number(again.getAttribute("data-reload-after")) || 5) * 1000);
  }

  // The pending-approvals badge.
  var badge = $("#pending-badge");
  if (badge && root.fetch) {
    var poll = function () {
      root.fetch("./api/pending", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) { badge.textContent = d.pending ? String(d.pending) : ""; badge.hidden = !d.pending; } })
        .catch(function () {});
    };
    setInterval(poll, 10000);
  }

  // Expiry countdowns.
  var cds = $$("[data-expires]");
  if (cds.length) {
    var tick = function () {
      var now = Date.now() / 1000;
      cds.forEach(function (el) {
        var left = Math.round(Number(el.getAttribute("data-expires")) - now);
        el.textContent = left > 0 ? Math.floor(left / 60) + " min " + (left % 60) + " s left" : "expired";
      });
    };
    tick(); setInterval(tick, 1000);
  }
})(typeof window !== "undefined" ? window : globalThis);
