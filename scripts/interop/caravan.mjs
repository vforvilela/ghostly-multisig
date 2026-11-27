// Writes test/vectors/caravan.json: Caravan's own PSBT code (@caravan/psbt, @caravan/bitcoin, as the Caravan web
// wallet uses them) against the spend in signing.json.
//
//   1. Caravan validates every signature in the copy the app merges (the app's real combine, run here).
//   2. Caravan's v0 -> v2 conversion of the bare PSBT: the app must refuse it with its version message.
//   3. Caravan's signature round trip: it lifts the Trezor's signatures out of its PSBT and adds them to the bare one,
//      as Caravan does with a signature set; the app must read that copy and finish Core's transaction from it.
//
//   node scripts/interop/caravan.mjs <a node_modules folder holding @caravan/psbt and @caravan/bitcoin>
//
// Node 24 runs the app's TypeScript directly (type stripping), so this needs no build.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { base64, hex } from "@scure/base";
import { combine, readPsbt } from "../../src/psbt.ts";

const [modules] = process.argv.slice(2);
if (!modules) throw new Error("usage: caravan.mjs <node_modules with @caravan/psbt and @caravan/bitcoin>");
const require = createRequire(resolve(modules, "..", "x.js"));
const psbtPkg = require("@caravan/psbt");
const bitcoinPkg = require("@caravan/bitcoin");
const { PsbtV2, validateMultisigPsbtSignature, getPsbtVersionNumber } = psbtPkg;
const { addSignaturesToPSBT, parseSignaturesFromPSBT } = bitcoinPkg;
const version = (name) => JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version;
const v = JSON.parse(readFileSync(new URL("../../test/vectors/signing.json", import.meta.url), "utf8"));

// 1. Every partial signature in the app's merge of Core's and the Trezor's copies, checked by Caravan.
const merged = combine(readPsbt(v.signedCore), readPsbt(v.signedTrezor));
const mergedB64 = base64.encode(merged.toPSBT(0));
let checked = 0;
for (let n = 0; n < merged.inputsLength; n++) {
  const input = merged.getInput(n);
  for (const [pubkey, sig] of input.partialSig ?? []) {
    const got = validateMultisigPsbtSignature(mergedB64, n, Buffer.from(sig), String(input.witnessUtxo.amount));
    if (got !== hex.encode(pubkey)) throw new Error(`Caravan rejected input ${n}'s signature by ${hex.encode(pubkey)}: ${got}`);
    checked++;
  }
}
if (checked !== 2 * merged.inputsLength) throw new Error(`expected two signatures per input, checked ${checked}`);

// 2. Caravan's v2 conversion.
const v2 = PsbtV2.FromV0(v.unsigned).serialize("base64");
if (getPsbtVersionNumber(v2) !== 2) throw new Error("Caravan did not make a v2 PSBT");

// 3. Caravan's signature round trip. It keys signatures by pubkey, and each input has its own derived key, so one
// signer's copy reads as one { pubkey: [signature] } entry per input, in input order.
const sets = Object.entries(parseSignaturesFromPSBT(v.signedTrezor));
if (sets.length !== merged.inputsLength || sets.some(([, s]) => s.length !== 1)) throw new Error(`expected one signature per input: ${JSON.stringify(sets)}`);
const caravanSigned = addSignaturesToPSBT("regtest", v.unsigned, sets.map(([k]) => Buffer.from(k, "hex")), sets.map(([, [s]]) => Buffer.from(s, "hex")));
if (!caravanSigned) throw new Error("Caravan could not add the signatures");

const doc = {
  source: `@caravan/psbt ${version("@caravan/psbt")}, @caravan/bitcoin ${version("@caravan/bitcoin")} on signing.json's spend`,
  generated: new Date().toISOString().slice(0, 10),
  validated: { psbt: mergedB64, signatures: checked },
  v2,
  caravanSigned,
};
writeFileSync(new URL("../../test/vectors/caravan.json", import.meta.url), `${JSON.stringify(doc, null, 1)}\n`);
console.log(`wrote caravan.json: Caravan validated ${checked} signatures in the app's merge`);
