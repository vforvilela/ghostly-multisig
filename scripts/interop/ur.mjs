// Writes test/vectors/ur.json: the app's UR encoder (src/ur.ts) against @ngraveio/bc-ur and
// @keystonehq/bc-ur-registry, the libraries Keystone's and Passport's companion apps use, on signing.json's PSBTs.
//
//   1. The reference's crypto-psbt for each PSBT, 3n parts (n pure, 2n mixed): the app must make every part the same.
//   2. The reference decoder reads the app's parts; the app's decoder reads the reference's mixed parts only.
//   3. uqr (the app's QR library) draws each part; jsQR reads it back as the same text.
//
//   node scripts/interop/ur.mjs <a node_modules folder holding @ngraveio/bc-ur, @keystonehq/bc-ur-registry, jsqr>
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { base64 } from "@scure/base";
import { encode as qr } from "uqr";
import { urDecode, urEncoder } from "../../src/ur.ts";

const [modules] = process.argv.slice(2);
if (!modules) throw new Error("usage: ur.mjs <node_modules with @ngraveio/bc-ur, @keystonehq/bc-ur-registry, jsqr>");
const require = createRequire(resolve(modules, "..", "x.js"));
const { UREncoder, URDecoder } = require("@ngraveio/bc-ur");
const { CryptoPSBT } = require("@keystonehq/bc-ur-registry");
const jsQR = require("jsqr");
const version = (name) => JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version;
const v = JSON.parse(readFileSync(new URL("../../test/vectors/signing.json", import.meta.url), "utf8"));

const FRAGMENT = 200;
function qrReads(text) {
  const { data, size } = qr(text.toUpperCase(), { ecc: "L", border: 2 });
  const scale = 4;
  const px = size * scale;
  const rgba = new Uint8ClampedArray(px * px * 4);
  for (let y = 0; y < px; y++)
    for (let x = 0; x < px; x++) {
      const c = data[Math.floor(y / scale)][Math.floor(x / scale)] ? 0 : 255;
      rgba.set([c, c, c, 255], (y * px + x) * 4);
    }
  const got = jsQR(rgba, px, px);
  if (!got || got.data !== text.toUpperCase()) throw new Error(`jsQR could not read the QR of ${text.slice(0, 30)}`);
}

const cases = {};
for (const name of ["unsigned", "signedCore", "signedTrezor"]) {
  const psbt = base64.decode(v[name]);
  const ref = new UREncoder(new CryptoPSBT(Buffer.from(psbt)).toUR(), FRAGMENT);
  const mine = urEncoder("crypto-psbt", psbt, FRAGMENT);
  if (mine.count !== ref.fragmentsLength) throw new Error(`${name}: ${mine.count} parts, the reference ${ref.fragmentsLength}`);
  const parts = Array.from({ length: 3 * mine.count }, () => ref.nextPart());
  parts.forEach((p, i) => {
    if (mine.part(i + 1) !== p) throw new Error(`${name} part ${i + 1} differs:\n${mine.part(i + 1)}\n${p}`);
    qrReads(p);
  });
  // The reference decoder on the app's pure parts.
  const dec = new URDecoder();
  for (let i = 1; i <= mine.count; i++) dec.receivePart(mine.part(i));
  if (!dec.isSuccess() || CryptoPSBT.fromCBOR(dec.resultUR().cbor).getPSBT().toString("base64") !== v[name]) throw new Error(`${name}: the reference could not read the app's parts`);
  // The app's decoder on mixed parts only (no pure fragment at all).
  const mixedOnly = parts.slice(mine.count);
  if (base64.encode(urDecode(mixedOnly.join("\n")).data) !== v[name]) throw new Error(`${name}: the app could not read mixed parts`);
  cases[name] = { count: mine.count, parts };
}

const doc = {
  source: `@ngraveio/bc-ur ${version("@ngraveio/bc-ur")}, @keystonehq/bc-ur-registry ${version("@keystonehq/bc-ur-registry")}, jsqr ${version("jsqr")} on signing.json's PSBTs, ${FRAGMENT}-byte fragments`,
  generated: new Date().toISOString().slice(0, 10),
  fragment: FRAGMENT,
  cases,
};
writeFileSync(new URL("../../test/vectors/ur.json", import.meta.url), `${JSON.stringify(doc, null, 1)}\n`);
console.log(`wrote ur.json: ${Object.entries(cases).map(([k, c]) => `${k} ${c.parts.length} parts`).join(", ")}, all equal to the reference and read back from QR`);
