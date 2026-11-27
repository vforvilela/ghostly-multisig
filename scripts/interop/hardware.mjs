// Writes test/vectors/hardware.json: for each hardware-wallet simulator, a 2-of-3 P2WSH wallet of Core's key A, the
// drongo key B (as an xpub only) and the device's own key. Core funds it on regtest, creates and signs the spend; the
// device registers the wallet and signs through HWI; Core finalises, accepts and mines. The unit tests check the app
// combines and finalises to the very same transaction.
//
//   node scripts/interop/hardware.mjs <runner, as JSON array> <device,...> <bitcoin-cli args for a fresh regtest node>
//
// The runner is what runs `hwi` and `python` in HWI's environment, e.g.
// '["docker","exec","-i","-w","/hwi","hwi-sims","/root/.local/bin/poetry","run"]' coldcard,bitbox02,ledger ...
// The simulators are the ones HWI's own tests use (test/setup_environment.sh), already running and initialised with
// their fixed test seeds: Coldcard (--ms --headless), BitBox02 (restore_device), Ledger (Speculos with HWI's automation),
// Jade (QEMU, set_seed).
import { execFileSync } from "node:child_process";
import { pbkdf2Sync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { HDKey } from "@scure/bip32";
import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer";

const [runnerJson, deviceList, ...node] = process.argv.slice(2);
if (!node.length) throw new Error("usage: hardware.mjs <runner JSON> <devices> <bitcoin-cli args>");
const [hwiBin, ...runner] = JSON.parse(runnerJson);
const hwiPre = [...runner, "hwi"];
// The wallet's account xpubs as PSBT_GLOBAL_XPUB records, as Sparrow writes them; the BitBox02 reads the multisig
// from them (Core leaves them out).
function withGlobalXpubs(psbt, keys) {
  const tx = Transaction.fromPSBT(base64.decode(psbt), { allowUnknownOutputs: true });
  const path = [48, 1, 0, 2].map((i) => i + 0x80000000);
  tx.global.xpub = keys.map(({ fp, xpub }) => {
    const k = HDKey.fromExtendedKey(xpub, TEST_VERSIONS);
    return [{ version: TEST_VERSIONS.public, depth: k.depth, parentFingerprint: k.parentFingerprint, childNumber: k.index, chainCode: k.chainCode, publicKey: k.publicKey }, { fingerprint: Number.parseInt(fp, 16), path }];
  });
  return base64.encode(tx.toPSBT(0));
}
const DEVICES_BITBOX = "127.0.0.1:15423";
const BITBOX02_REGISTER = `
import sys
from hwilib.common import Chain
from hwilib.psbt import PSBT
from hwilib.devices.bitbox02 import Bitbox02Client
from hwilib.devices.bitbox02_lib.bitbox02 import btc
c = Bitbox02Client("${DEVICES_BITBOX}"); c.chain = Chain.REGTEST
p = PSBT(); p.deserialize(sys.stdin.read().strip())
_, sc = c._multisig_scriptconfig(2, p.xpub, btc.BTCScriptConfig.Multisig.P2WSH)
c._maybe_register_script_config(sc.script_config, sc.keypath, "ghostly-interop")
c.close()
`;
const TEST_VERSIONS = { private: 0x04358394, public: 0x043587cf };
const raw = (...args) => execFileSync("bitcoin-cli", [...node, ...args], { encoding: "utf8" }).trim();
const cli = (...args) => JSON.parse(raw(...args));
const wallet = (name) => (...args) => JSON.parse(raw(`-rpcwallet=${name}`, ...args));
const address = (name) => raw(`-rpcwallet=${name}`, "getnewaddress");
const withSum = (d) => `${d}#${cli("getdescriptorinfo", d).checksum}`;

const DEVICES = {
  coldcard: { type: "coldcard", path: "/tmp/ckcc-simulator.sock" },
  bitbox02: { type: "bitbox02", path: DEVICES_BITBOX },
  ledger: { type: "ledger", path: "tcp:127.0.0.1:9999" },
  jade: { type: "jade", path: "tcp:127.0.0.1:30121" },
};
const hwi = (device, ...args) => {
  const { type, path } = DEVICES[device];
  const out = JSON.parse(execFileSync(hwiBin, [...hwiPre, "--chain", "regtest", "-t", type, "-d", path, ...args], { encoding: "utf8", maxBuffer: 1 << 24 }));
  if (out.error) throw new Error(`${device} ${args[0]}: ${out.error}`);
  return out;
};

const PATH = "m/48'/1'/0'/2'";
const ORIGIN = "48h/1h/0h/2h";
const TEST = { private: 0x04358394, public: 0x043587cf };
const fpOf = (k) => k.fingerprint.toString(16).padStart(8, "0");
const masterA = HDKey.fromMasterSeed(new Uint8Array(32).fill(0x0a), TEST);
const accountA = masterA.derive(PATH);
const seedB = pbkdf2Sync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".normalize("NFKD"), "mnemonic", 2048, 64, "sha512");
const masterB = HDKey.fromMasterSeed(seedB, TEST);
const keyB = `[${fpOf(masterB)}/${ORIGIN}]${masterB.derive(PATH).publicExtendedKey}`;

raw("createwallet", "miner");
raw("generatetoaddress", "101", address("miner"));
const core = raw("-version").split("\n")[0];
const hwiVersion = execFileSync(hwiBin, [...hwiPre, "--version"], { encoding: "utf8" }).trim().split(" ").at(-1);

const enumerated = JSON.parse(execFileSync(hwiBin, [...hwiPre, "--emulators", "enumerate"], { encoding: "utf8" }));
const doc = { source: `${core} (key A, creator, finaliser); HWI ${hwiVersion} (git e63a0af) simulators (device key), regtest`, generated: new Date().toISOString().slice(0, 10), devices: {} };
for (const device of deviceList.split(",")) {
  const fpDevice = enumerated.find((d) => d.path === DEVICES[device].path)?.fingerprint;
  if (!fpDevice) throw new Error(`${device}: not running at ${DEVICES[device].path}`);
  const xpub = hwi(device, "getxpub", PATH.replaceAll("'", "h")).xpub;
  const desc = (a, tail) => `wsh(sortedmulti(2,[${fpOf(masterA)}/${ORIGIN}]${a}${tail},${keyB}${tail},[${fpDevice}/${ORIGIN}]${xpub}${tail}))`;
  const descriptor = withSum(desc(accountA.publicExtendedKey, "/<0;1>/*"));

  const name = `ms-${device}`;
  raw("createwallet", name, "false", "true");
  const imported = wallet(name)(
    "importdescriptors",
    JSON.stringify([0, 1].map((b) => ({ desc: withSum(desc(accountA.privateExtendedKey, `/${b}/*`)), active: true, internal: b === 1, timestamp: "now", range: [0, 20] }))),
  );
  if (!imported.every((r) => r.success)) throw new Error(`importdescriptors: ${JSON.stringify(imported)}`);
  for (const amount of ["0.6", "0.7"]) raw("-rpcwallet=miner", "sendtoaddress", address(name), amount);
  raw("generatetoaddress", "1", address("miner"));

  const payee = address("miner");
  const { psbt: unsigned } = wallet(name)("walletcreatefundedpsbt", "[]", JSON.stringify([{ [payee]: 1 }]), "0", JSON.stringify({ fee_rate: 5 }));
  const { psbt: signedCore } = wallet(name)("walletprocesspsbt", unsigned, "true", "ALL", "true", "false");

  // The BitBox02 takes the multisig from the PSBT's global xpubs, which Core leaves out. HWI's registerdescriptor sends
  // it no account keypath and its signtx no name, and the firmware refuses both; registered with both, signtx goes on.
  const bitbox = device === "bitbox02";
  const sent = bitbox
    ? withGlobalXpubs(unsigned, [{ fp: fpOf(masterA), xpub: accountA.publicExtendedKey }, { fp: fpOf(masterB), xpub: masterB.derive(PATH).publicExtendedKey }, { fp: fpDevice, xpub }])
    : unsigned;
  if (bitbox) execFileSync(hwiBin, [...runner, "python", "-c", BITBOX02_REGISTER], { input: sent, encoding: "utf8" });
  const registered = bitbox ? [] : ["--registration", hwi(device, "registerdescriptor", "ghostly-interop", descriptor).registration];
  const signedDevice = hwi(device, "signtx", sent, ...registered).psbt;
  if (signedDevice === sent) throw new Error(`${device} added no signature`);

  const done = cli("finalizepsbt", raw("combinepsbt", JSON.stringify([signedCore, signedDevice])));
  if (!done.complete) throw new Error(`${device}: Core could not finalise`);
  const [accept] = cli("testmempoolaccept", JSON.stringify([done.hex]));
  if (!accept.allowed) throw new Error(`${device}: Core refused the transaction: ${accept["reject-reason"]}`);
  const txid = raw("sendrawtransaction", done.hex);
  raw("generatetoaddress", "1", address("miner"));
  if (wallet(name)("gettransaction", txid).confirmations !== 1) throw new Error(`${device}: the transaction did not confirm`);

  doc.devices[device] = { descriptor, fingerprints: { core: fpOf(masterA), drongo: fpOf(masterB), device: fpDevice }, payee, unsigned, sent, signedCore, signedDevice, final: done.hex, txid };
  console.log(`${device}: ${txid} confirmed`);
}
writeFileSync(new URL("../../test/vectors/hardware.json", import.meta.url), `${JSON.stringify(doc, null, 1)}\n`);
console.log(`wrote hardware.json: ${Object.keys(doc.devices).join(", ")}`);
