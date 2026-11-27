// Writes test/vectors/signing.json: a 2-of-3 P2WSH spend on regtest, created and signed by Bitcoin Core (key A), and
// signed by Sparrow's drongo library (key B) and by a Trezor Model T emulator through HWI (key C). Core combines and
// finalises each pair, and every three-way merge, accepts each into its mempool test, and mines the Core + drongo one;
// the unit tests check the app makes the very same transactions from the parts.
//
//   node scripts/interop/signing.mjs <java> <drongo classpath file> <bitcoin-cli args for a fresh regtest node>
//
// The Trezor: trezor-user-env running (docker run --rm --network host ghcr.io/trezor/trezor-user-env) and hwi on PATH.
// The script starts and seeds the emulator itself, and presses its buttons.
//
// The node needs -fallbackfee (or the fee is set below) and nothing else; the script makes its own wallets.
import { execFileSync, spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { HDKey } from "@scure/bip32";
import { hex } from "@scure/base";
import { controller } from "./trezor.mjs";

const [java, cpFile, ...node] = process.argv.slice(2);
if (!node.length) throw new Error("usage: signing.mjs <java> <drongo classpath file> <bitcoin-cli args>");
const raw = (...args) => execFileSync("bitcoin-cli", [...node, ...args], { encoding: "utf8" }).trim();
const cli = (...args) => JSON.parse(raw(...args));
const wallet = (name) => (...args) => JSON.parse(raw(`-rpcwallet=${name}`, ...args));
const address = (name) => raw(`-rpcwallet=${name}`, "getnewaddress");
const core = raw("-version").split("\n")[0];

const signer = new URL("DrongoSign.java", import.meta.url).pathname;
const drongo = (input, ...args) =>
  execFileSync(java, ["--enable-native-access=ALL-UNNAMED", "-cp", readFileSync(cpFile, "utf8").trim(), signer, ...args], {
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "ignore"],
  }).trim().split("\n").at(-1);

const PATH = "m/48'/1'/0'/2'";
const ORIGIN = "48h/1h/0h/2h";
// Key A: Core holds the private key. Keys B and C: BIP 39 test mnemonics, held by drongo.
const TEST = { private: 0x04358394, public: 0x043587cf };
const master = HDKey.fromMasterSeed(new Uint8Array(32).fill(0x0a), TEST);
const accountA = master.derive(PATH);
const fpA = master.fingerprint.toString(16).padStart(8, "0");
const MNEMONIC_B = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_C = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const [fpB, tpubB] = drongo("", "xpub", MNEMONIC_B, PATH).split(" ");
const [fpC, tpubC] = drongo("", "xpub", MNEMONIC_C, PATH).split(" ");

const desc = (a, tail) => `wsh(sortedmulti(2,[${fpA}/${ORIGIN}]${a}${tail},[${fpB}/${ORIGIN}]${tpubB}${tail},[${fpC}/${ORIGIN}]${tpubC}${tail}))`;
const withSum = (d) => `${d}#${cli("getdescriptorinfo", d).checksum}`;
const publicDescriptor = withSum(desc(accountA.publicExtendedKey, "/<0;1>/*"));

// The Trezor holds key C; it must derive what drongo derived from the same words.
const TREZOR = "udp:127.0.0.1:21324";
const FIRMWARE = "2.13.1";
await controller([
  { type: "emulator-start", model: "T2T1", version: FIRMWARE, wipe: true },
  { type: "emulator-setup", mnemonic: MNEMONIC_C, pin: "", passphrase_protection: false, label: "interop" },
]);
const hwi = (...args) => JSON.parse(execFileSync("hwi", ["-t", "trezor", "-d", TREZOR, "--chain", "regtest", ...args], { encoding: "utf8" }));
if (hwi("getxpub", PATH.replaceAll("'", "h")).xpub !== tpubC) throw new Error("the Trezor and drongo derive different keys");

/** HWI signtx, pressing YES on the emulator for every screen until it answers. */
async function trezorSign(psbt) {
  const child = spawn("hwi", ["-t", "trezor", "-d", TREZOR, "--chain", "regtest", "signtx", psbt]);
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  let done = false;
  const exit = new Promise((ok) => child.on("exit", (code) => ((done = true), ok(code))));
  while (!done) {
    await new Promise((ok) => setTimeout(ok, 700));
    if (!done) await controller([{ type: "emulator-press-yes" }]).catch(() => {});
  }
  if ((await exit) !== 0) throw new Error(`hwi signtx failed: ${out}`);
  const reply = JSON.parse(out);
  if (!reply.psbt) throw new Error(`hwi signtx: ${out}`);
  return reply.psbt;
}

// Core: a miner wallet, and the multisig wallet holding key A's private half.
raw("createwallet", "miner");
raw("createwallet", "ms", "false", "true");
const imported = wallet("ms")(
  "importdescriptors",
  JSON.stringify([0, 1].map((b) => ({ desc: withSum(desc(accountA.privateExtendedKey, `/${b}/*`)), active: true, internal: b === 1, timestamp: "now", range: [0, 20] }))),
);
if (!imported.every((r) => r.success)) throw new Error(`importdescriptors: ${JSON.stringify(imported)}`);
const miner = wallet("miner");
raw("generatetoaddress", "101", address("miner"));
// Two coins, so the PSBT has two inputs.
for (const amount of ["0.6", "0.7"]) raw(`-rpcwallet=miner`, "sendtoaddress", address("ms"), amount);
raw("generatetoaddress", "1", address("miner"));

const payee = address("miner");
const { psbt: unsigned } = wallet("ms")("walletcreatefundedpsbt", "[]", JSON.stringify([{ [payee]: 1 }]), "0", JSON.stringify({ fee_rate: 5 }));
const { psbt: signedCore } = wallet("ms")("walletprocesspsbt", unsigned, "true", "ALL", "true", "false");
const signedDrongo = drongo(unsigned, "sign", MNEMONIC_B, PATH, publicDescriptor);
const signedBoth = drongo(signedCore, "sign", MNEMONIC_B, PATH, publicDescriptor); // the usual relay: one after the other
const signedTrezor = await trezorSign(unsigned);

/** Core's own combine + finalise of these copies, which its mempool must accept. */
function coreFinal(...copies) {
  const done = cli("finalizepsbt", raw("combinepsbt", JSON.stringify(copies)));
  if (!done.complete) throw new Error("Core could not finalise");
  const [accept] = cli("testmempoolaccept", JSON.stringify([done.hex]));
  if (!accept.allowed) throw new Error(`Core refused the transaction: ${accept["reject-reason"]}`);
  return done.hex;
}
const finalCoreTrezor = coreFinal(signedCore, signedTrezor);
const finalDrongoTrezor = coreFinal(signedDrongo, signedTrezor);
const finalAll = coreFinal(signedCore, signedDrongo, signedTrezor);

const combined = raw("combinepsbt", JSON.stringify([signedCore, signedDrongo]));
const finished = cli("finalizepsbt", combined);
if (!finished.complete) throw new Error("Core could not finalise the combined PSBT");
const [accept] = cli("testmempoolaccept", JSON.stringify([finished.hex]));
if (!accept.allowed) throw new Error(`Core refused the transaction: ${accept["reject-reason"]}`);
const sequential = cli("finalizepsbt", signedBoth);
if (sequential.hex !== finished.hex) throw new Error("drongo signing Core's copy gave a different transaction");
const txid = raw("sendrawtransaction", finished.hex);
raw("generatetoaddress", "1", address("miner"));
if (wallet("ms")("gettransaction", txid).confirmations !== 1) throw new Error("the transaction did not confirm");

const doc = {
  source: `${core} (key A, creator, combiner, finaliser), sparrowwallet/drongo Wallet.sign (key B), Trezor T2T1 emulator firmware ${FIRMWARE} via HWI ${execFileSync("hwi", ["--version"], { encoding: "utf8" }).trim().split(" ").at(-1)} (key C), regtest`,
  generated: new Date().toISOString().slice(0, 10),
  descriptor: publicDescriptor,
  fingerprints: { core: fpA, drongo: fpB, trezor: fpC },
  payee,
  unsigned,
  signedCore,
  signedDrongo,
  signedBoth,
  signedTrezor,
  final: finished.hex,
  finalCoreTrezor,
  finalDrongoTrezor,
  finalAll,
  txid,
};
writeFileSync(new URL("../../test/vectors/signing.json", import.meta.url), `${JSON.stringify(doc, null, 1)}\n`);
console.log(`wrote signing.json: ${txid} confirmed, ${hex.decode(finished.hex).length} bytes`);
