// Crypto core tests. Run from the repo root: node tests/core.test.mjs
// Writes sample encrypted output to tests/out/ for tests/interop_test.py.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import assert from "node:assert/strict";

const html = readFileSync(process.argv[2] || new URL("../index.html", import.meta.url), "utf8");
const core = html.split("/* CORE-START */")[1].split("/* CORE-END */")[0];
const A256 = new Function(core + "; return A256;")();
const te = new TextEncoder(), td = new TextDecoder();
const out = process.argv[3] || new URL("./out", import.meta.url).pathname;
mkdirSync(out, { recursive: true });

let n = 0;
const ok = (name) => console.log(`ok ${++n} - ${name}`);
async function rejects(p, re, name) {
  try { await p; assert.fail("expected rejection: " + name); }
  catch (e) { assert.ok(e instanceof A256.UserError, name + ": not a UserError: " + e); if (re) assert.match(e.message, re); }
  ok(name);
}

// 1. passphrase text round trip (default 600k iterations)
const msg = "Wire instructions for invoice #2041. Xin chào, Tuấn! 🔐";
const s1 = await A256.seal(te.encode(msg), { pass: "correct horse battery staple" });
const b64 = A256.toB64(s1.bytes);
assert.equal(s1.bytes.length, 6 + 20 + 12 + te.encode(msg).length + 16);
const r1 = await A256.open(A256.fromB64(b64), { pass: "correct horse battery staple" });
assert.equal(td.decode(r1.plaintext), msg);
assert.equal(r1.env.iters, 600000);
ok(`passphrase text round trip (kdf ${s1.kdfMs.toFixed(0)} ms)`);
writeFileSync(`${out}/text_pass.txt`, b64);

// 2. raw key round trip, hex and base64 key forms
const hex = A256.randomKeyHex();
const k = A256.parseRawKey(hex);
assert.ok(k.ok && k.fmt === "hex" && k.bytes.length === 32);
const s2 = await A256.seal(te.encode("raw key message"), { rawKey: k.bytes });
assert.equal(s2.bytes.length, 6 + 12 + 15 + 16);
const kb = A256.parseRawKey(Buffer.from(k.bytes).toString("base64"));
assert.ok(kb.ok && kb.fmt === "base64");
const r2 = await A256.open(s2.bytes, { rawKey: kb.bytes });
assert.equal(td.decode(r2.plaintext), "raw key message");
ok("raw key round trip (hex in, base64 out)");
writeFileSync(`${out}/text_raw.txt`, A256.toB64(s2.bytes));
writeFileSync(`${out}/text_raw.key`, hex);

// 3. wrong passphrase / wrong key
await rejects(A256.open(s1.bytes, { pass: "correct horse battery stapler" }), /Wrong passphrase/, "wrong passphrase rejected");
await rejects(A256.open(s2.bytes, { rawKey: A256.parseRawKey(A256.randomKeyHex()).bytes }), /Wrong key/, "wrong key rejected");

// 4. tampering: header (salt), nonce, ciphertext, tag, flags
for (const [label, idx] of [["salt", 12], ["nonce", 30], ["ciphertext", 40], ["tag", s1.bytes.length - 1]]) {
  const t = s1.bytes.slice(); t[idx] ^= 1;
  await rejects(A256.open(t, { pass: "correct horse battery staple" }), /changed/, `tampered ${label} rejected`);
}
{ const t = s1.bytes.slice(); t[5] = 3; // claim it is a file
  await rejects(A256.open(t, { pass: "correct horse battery staple" }), /changed/, "tampered flags rejected (AAD)"); }
{ const t = s1.bytes.slice(); new DataView(t.buffer).setUint32(6, 0xffffffff);
  await rejects(A256.open(t, { pass: "x" }), /out of range/, "absurd iteration count refused before KDF"); }

// 5. missing key type
try { await A256.open(s1.bytes, { rawKey: k.bytes }); assert.fail(); }
catch (e) { assert.ok(e instanceof A256.KeyNeeded && e.need === "pass"); }
try { await A256.open(s2.bytes, { pass: "something" }); assert.fail(); }
catch (e) { assert.ok(e instanceof A256.KeyNeeded && e.need === "raw"); }
ok("KeyNeeded reports which key the envelope requires");

// 6. NFC normalization: composed vs decomposed Vietnamese passphrase
const nfc = "Nguyễn Anh Tuấn".normalize("NFC"), nfd = nfc.normalize("NFD");
assert.notEqual(nfc, nfd);
const s6 = await A256.seal(te.encode("diacritics"), { pass: nfd });
assert.equal(td.decode((await A256.open(s6.bytes, { pass: nfc })).plaintext), "diacritics");
ok("NFD-typed passphrase decrypts with NFC-typed passphrase");

// 7. file payload with unicode name, armored, big-ish (3 MB random)
const fileData = new Uint8Array(3 * 1024 * 1024 + 7);
for (let i = 0; i < fileData.length; i += 65536) crypto.getRandomValues(fileData.subarray(i, i + 65536));
const s7 = await A256.seal(A256.packFile("Báo cáo Q3 — final.pdf", fileData), { pass: "file pass", isFile: true });
const armored = A256.armor(A256.toB64(s7.bytes), "AES-256-GCM ENCRYPTED FILE");
assert.ok(armored.startsWith("-----BEGIN AES-256-GCM ENCRYPTED FILE-----\n"));
const r7 = await A256.open(A256.fromB64(armored), { pass: "file pass" });
assert.ok(r7.env.flags & A256.FLAG_FILE);
const f7 = A256.unpackFile(r7.plaintext);
assert.equal(f7.name, "Báo cáo Q3 — final.pdf");
assert.deepEqual(Buffer.from(f7.data), Buffer.from(fileData));
ok("3 MB file round trip through armored base64, name preserved");
writeFileSync(`${out}/file_pass.aes.txt`, armored);
writeFileSync(`${out}/file_plain.bin`, fileData);

// 8. long file name truncated to <=255 UTF-8 bytes without breaking characters
const longName = "ấ".repeat(200) + ".txt";
const packed = A256.packFile(longName, new Uint8Array([1, 2, 3]));
const up = A256.unpackFile(packed);
assert.ok(te.encode(up.name).length <= 255 && !up.name.includes("�"));
ok("long file name truncated on a character boundary");

// 9. base64 parsing edge cases
assert.deepEqual(A256.fromB64("  " + b64.slice(0, 40) + "\n" + b64.slice(40) + "\n"), A256.fromB64(b64));
assert.deepEqual(A256.fromB64(b64.replace(/=+$/, "")), A256.fromB64(b64));
assert.deepEqual(A256.fromB64(b64.replace(/\+/g, "-").replace(/\//g, "_")), A256.fromB64(b64));
await rejects(Promise.resolve().then(() => A256.fromB64("hello world!")), /base64/, "non-base64 rejected");
await rejects(Promise.resolve().then(() => A256.fromB64("")), /Paste/, "empty input rejected");
await rejects(Promise.resolve().then(() => A256.parseEnvelope(A256.fromB64("aGVsbG8gd29ybGQ="))), /header/, "non-A256 data rejected");
await rejects(Promise.resolve().then(() => A256.parseEnvelope(s1.bytes.subarray(0, 40))), /too short/, "truncated envelope rejected");
ok("base64: whitespace, missing padding, url-safe alphabet accepted");

// 10. raw key parsing messages
assert.match(A256.parseRawKey("abcd").msg, /4 hex characters/);
assert.match(A256.parseRawKey(Buffer.alloc(16).toString("base64")).msg, /16 bytes/);
assert.equal(A256.parseRawKey("   ").empty, true);
assert.equal(A256.parseRawKey(hex.match(/.{8}/g).join(" ")).ok, true);
ok("raw key validation messages");

// 11. empty text encrypts
const s11 = await A256.seal(new Uint8Array(0), { rawKey: k.bytes });
assert.equal((await A256.open(s11.bytes, { rawKey: k.bytes })).plaintext.length, 0);
ok("empty payload round trip");

// 12. unique nonce/salt per message
const a = await A256.seal(te.encode("same"), { rawKey: k.bytes }), b = await A256.seal(te.encode("same"), { rawKey: k.bytes });
assert.notDeepEqual(a.bytes, b.bytes);
ok("same input encrypts differently each time");

// 13. zip wrapper
const zipped = new Uint8Array(await A256.zipOne("tài liệu.kdbx", new Uint8Array([9, 8, 7, 6]), new Date(2026, 10, 19, 14, 30, 10)).arrayBuffer());
writeFileSync(`${out}/wrapped.zip`, zipped);
assert.equal(A256.crc32(te.encode("123456789")), 0xcbf43926);
ok("zip written, crc32 check value matches");

console.log(`\n${n} checks passed`);
