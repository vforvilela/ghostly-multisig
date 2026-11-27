// Writes test/vectors/electrum.json: Electrum (its Multisig_Wallet.sign_transaction) as a co-signer of the spend in
// signing.json. It signs the bare PSBT with key B, signs the Trezor's copy with key B, and signs Core's copy with key C.
// Core combines and finalises each; the results must be the transactions Core already accepted in signing.mjs.
//
//   node scripts/interop/electrum.mjs <python with electrum> <bitcoin-cli args for any regtest node>
//
// Electrum is not on PyPI: pip install "<clone of spesmilo/electrum at a release tag>[crypto]".
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const [python, ...node] = process.argv.slice(2);
if (!node.length) throw new Error("usage: electrum.mjs <python> <bitcoin-cli args>");
const raw = (...args) => execFileSync("bitcoin-cli", [...node, ...args], { encoding: "utf8" }).trim();
const cli = (...args) => JSON.parse(raw(...args));
const v = JSON.parse(readFileSync(new URL("../../test/vectors/signing.json", import.meta.url), "utf8"));

const PATH = "m/48'/1'/0'/2'";
const MNEMONIC = {
  [v.fingerprints.drongo]: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  [v.fingerprints.trezor]: "legal winner thank year wave sausage worth useful legal winner thank yellow",
};
const keys = [...v.descriptor.matchAll(/\[([0-9a-f]{8})\/[^\]]+\](tpub\w+)/g)].map((m) => ({ fp: m[1], tpub: m[2] }));
const script = new URL("electrum_sign.py", import.meta.url).pathname;
const electrum = (fp, psbt) =>
  execFileSync(python, ["-I", script, MNEMONIC[fp], PATH, "2", ...keys.filter((k) => k.fp !== fp).map((k) => `${k.fp}:${k.tpub}`)], {
    encoding: "utf8",
    input: psbt,
    stdio: ["pipe", "pipe", "ignore"],
  }).trim().split("\n").slice(-2);

function coreFinal(...copies) {
  const done = cli("finalizepsbt", raw("combinepsbt", JSON.stringify(copies)));
  if (!done.complete) throw new Error("Core could not finalise");
  return done.hex;
}
const expect = (got, want, what) => {
  if (got !== want) throw new Error(`${what}: Core made a different transaction (${got.slice(0, 16)}… vs ${want.slice(0, 16)}…)`);
};

const [signedElectrum, exported] = electrum(v.fingerprints.drongo, v.unsigned);
if (exported !== signedElectrum) throw new Error("Electrum exported something other than its PSBT while incomplete");
expect(coreFinal(v.signedCore, signedElectrum), v.final, "Core + Electrum (B)");
// With the second signature Electrum finishes the transaction itself, and exports it raw.
const [electrumOnTrezor, electrumOnTrezorRaw] = electrum(v.fingerprints.drongo, v.signedTrezor);
expect(coreFinal(electrumOnTrezor), v.finalDrongoTrezor, "Electrum (B) on the Trezor's copy");
expect(electrumOnTrezorRaw, v.finalDrongoTrezor, "Electrum's own finished transaction (B on the Trezor's copy)");
// Key C: Electrum's signature is not the Trezor's byte for byte (each picks its nonce its own way), so the witness
// differs; the transaction (txid) must not, and Electrum's own finish must equal Core's.
const [electrumOnCore, electrumOnCoreRaw] = electrum(v.fingerprints.trezor, v.signedCore);
const finalCoreElectrum = coreFinal(electrumOnCore);
expect(cli("decoderawtransaction", finalCoreElectrum).txid, v.txid, "Electrum (C) on Core's copy");
expect(electrumOnCoreRaw, finalCoreElectrum, "Electrum's own finished transaction (C on Core's copy)");

const version = execFileSync(python, ["-I", "-c", "import electrum; print(electrum.version.ELECTRUM_VERSION)"], { encoding: "utf8" }).trim();
const doc = {
  source: `Electrum ${version} Multisig_Wallet.sign_transaction on signing.json's spend; Core finalised each and matched signing.json`,
  generated: new Date().toISOString().slice(0, 10),
  signedElectrum,
  electrumOnTrezor,
  electrumOnTrezorRaw,
  electrumOnCore,
  electrumOnCoreRaw,
  finalCoreElectrum,
};
writeFileSync(new URL("../../test/vectors/electrum.json", import.meta.url), `${JSON.stringify(doc, null, 1)}\n`);
console.log("wrote electrum.json: all three match Core's transactions");
