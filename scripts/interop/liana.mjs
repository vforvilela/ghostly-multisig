// Writes test/vectors/liana.json: a Liana wallet on regtest, run by Liana's own daemon (lianad), with Bitcoin Core as
// the node and as each co-signer's signer.
//
// The wallet has three spending paths, the shape Liana's compiler gives (liana/src/descriptors/mod.rs tests):
//   primary:               2 of A, B                    (keys at <0;1>/*)
//   recovery after 10:     2 of A, C                    (A again, at <2;3>/*: one key reused on another path)
//   recovery after 20:     2 of A, B, C                 (all at <4;5>/*)
//
//   1. lianad hands out two receive addresses; Core funds them.
//   2. Primary spend: lianad creates it (createspend, with change); key A (one Core wallet) and key B (another) sign
//      it apart; lianad merges both (updatespend), finalises and broadcasts it (broadcastspend). Core mines it.
//   3. Recovery spend: 10 blocks are mined; lianad creates the sweep of both coins (the other one, and the change)
//      through the 10-block path (createrecovery, nSequence 10); A and C sign it apart; lianad merges, finalises and
//      broadcasts it; Core mines it. Each Core signer signs for every key it holds, on every path; with nSequence 10 the
//      20-block path is closed, so the only spend is the 10-block one, and it needs both.
// The unit tests (test/unit/liana-interop.test.ts) check the app reads the wallet, names the signers, merges the copies
// in either order, finalises each to the very transaction lianad broadcast, and warns on the recovery spend.
//
//   node scripts/interop/liana.mjs <folder with lianad> <work folder> <bitcoin-cli args for a fresh regtest node>
//
// e.g. node scripts/interop/liana.mjs ~/liana-16.0-x86_64-linux-gnu /tmp/liana -regtest -rpcport=18743 -datadir=/tmp/btc
// The node needs -fallbackfee=0.0001 and -txindex=1. Liana 16.0's release binary (liana-16.0-x86_64-linux-gnu.tar.gz,
// its sha256 in liana-16.0-shasums.txt, signed by Edouard Paris's key 5B63F3B97699C7EEF3B040B19B7F629A53E77B83).
// lianad's socket path must be short (SUN_LEN), so the script runs it in the work folder with a relative data dir.
//
// The keys are fixed test seeds (32 bytes of 0x1a, 0x1b, 0x1c): never send real coins to them. The vectors hold only
// their xpubs.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { join, resolve } from "node:path";
import { HDKey } from "@scure/bip32";

const [lianaDir, workArg, ...node] = process.argv.slice(2);
if (!node.length) throw new Error("usage: liana.mjs <folder with lianad> <work folder> <bitcoin-cli args>");
const arg = (name) => node.find((a) => a.startsWith(`-${name}=`))?.slice(name.length + 2);
const rpcport = arg("rpcport");
const datadir = arg("datadir");
if (!rpcport || !datadir) throw new Error("give the node's -rpcport and -datadir: lianad needs them");
const work = resolve(workArg);
const vectors = new URL("../../test/vectors/liana.json", import.meta.url);

const raw = (...args) => execFileSync("bitcoin-cli", [...node, ...args], { encoding: "utf8" }).trim();
const cli = (...args) => JSON.parse(raw(...args));
const wallet = (name) => (...args) => JSON.parse(raw(`-rpcwallet=${name}`, ...args));
const withSum = (d) => `${d}#${cli("getdescriptorinfo", d).checksum}`;

const TEST = { private: 0x04358394, public: 0x043587cf };
const PATH = "m/48'/1'/0'/2'";
const ORIGIN = "48'/1'/0'/2'";
const fpOf = (k) => k.fingerprint.toString(16).padStart(8, "0");
const keys = Object.fromEntries(
  [["A", 0x1a], ["B", 0x1b], ["C", 0x1c]].map(([name, byte]) => {
    const master = HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), TEST);
    const account = master.derive(PATH);
    const origin = `[${fpOf(master)}/${ORIGIN}]`;
    return [name, { fp: fpOf(master), pub: `${origin}${account.publicExtendedKey}`, prv: `${origin}${account.privateExtendedKey}` }];
  }),
);
// The descriptor with every key public, or with `signer`'s keys private (that co-signer's Core wallet).
const descriptor = (signer) => {
  const k = (name, pair) => `${name === signer ? keys[name].prv : keys[name].pub}/<${pair}>/*`;
  return `wsh(or_i(and_v(v:thresh(2,pkh(${k("A", "4;5")}),a:pkh(${k("B", "4;5")}),a:pkh(${k("C", "4;5")})),older(20)),` +
    `or_d(multi(2,${k("A", "0;1")},${k("B", "0;1")}),and_v(v:thresh(2,pkh(${k("A", "2;3")}),a:pkh(${k("C", "0;1")})),older(10)))))`;
};

// ---------- lianad ----------
rmSync(work, { recursive: true, force: true });
mkdirSync(join(work, "ld"), { recursive: true });
const walletDescriptor = withSum(descriptor(null));
writeFileSync(join(work, "config.toml"), [
  'data_dir = "ld"',
  'log_level = "info"',
  `main_descriptor = "${walletDescriptor}"`,
  "[bitcoin_config]",
  'network = "regtest"',
  "poll_interval_secs = 1",
  "[bitcoind_config]",
  `addr = "127.0.0.1:${rpcport}"`,
  `cookie_path = "${resolve(datadir, "regtest", ".cookie")}"`,
  "",
].join("\n"));
const lianad = spawn(join(lianaDir, "lianad"), ["--conf", "config.toml"], { cwd: work, stdio: ["ignore", "ignore", "inherit"] });
const version = spawnSync(join(lianaDir, "lianad"), ["--version"], { encoding: "utf8" });
const lianaVersion = `lianad ${(version.stdout || version.stderr).trim().split("\n")[0]}`;
process.chdir(work);
let rpcId = 0;
function liana(method, params = {}) {
  return new Promise((ok, fail) => {
    const socket = connect("ld/regtest/lianad_rpc");
    let text = "";
    socket.on("error", fail);
    socket.on("data", (d) => {
      text += d;
      let reply;
      try {
        reply = JSON.parse(text);
      } catch {
        return;
      }
      socket.destroy();
      if (reply.error) fail(new Error(`lianad ${method}: ${JSON.stringify(reply.error)}`));
      else ok(reply.result);
    });
    // lianad reads one request per line.
    socket.write(`${JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params })}\n`);
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(what, test) {
  for (let i = 0; i < 120; i++) {
    try {
      const got = await test();
      if (got) return got;
    } catch (e) {
      if (i === 119) throw e;
    }
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

try {
  await until("lianad's socket", () => liana("getinfo"));
  const core = raw("-version").split("\n")[0];
  raw("createwallet", "miner");
  const mine = (n) => raw("generatetoaddress", String(n), raw("-rpcwallet=miner", "getnewaddress"));
  mine(101);
  // One Core wallet per co-signer, holding that co-signer's private key in the wallet's descriptor.
  for (const name of ["A", "B", "C"]) {
    raw("-named", "createwallet", `wallet_name=sign${name}`, "blank=true");
    const [imported] = wallet(`sign${name}`)("importdescriptors", JSON.stringify([{ desc: withSum(descriptor(name)), timestamp: "now", active: false }]));
    if (!imported.success) throw new Error(`Core did not import ${name}'s descriptor: ${JSON.stringify(imported)}`);
  }
  const sign = (name, psbt) => {
    const out = wallet(`sign${name}`)("-named", "walletprocesspsbt", `psbt=${psbt}`, "sign=true", "finalize=false");
    if (out.psbt === psbt) throw new Error(`Core's key ${name} added no signature`);
    return out.psbt;
  };
  const synced = (height) => until(`lianad at height ${height}`, async () => (await liana("getinfo")).block_height >= height);

  // 1. Funds.
  const receive = [];
  for (let i = 0; i < 2; i++) receive.push((await liana("getnewaddress")).address);
  for (const [i, address] of receive.entries()) raw("-rpcwallet=miner", "sendtoaddress", address, i ? "0.3" : "0.5");
  mine(1);
  await synced(cli("getblockcount"));
  await until("lianad's two coins", async () => (await liana("listcoins")).coins.filter((c) => c.block_height).length === 2);
  const coins = (await liana("listcoins")).coins;

  // 2. Primary spend: one coin, part of it out, the rest back as change.
  const primaryCoin = coins.find((c) => c.amount === 50_000_000);
  const external = raw("-rpcwallet=miner", "getnewaddress");
  const spend = await liana("createspend", { destinations: { [external]: 20_000_000 }, outpoints: [primaryCoin.outpoint], feerate: 2 });
  const primary = { unsigned: spend.psbt };
  primary.signedA = sign("A", spend.psbt);
  primary.signedB = sign("B", spend.psbt);
  await liana("updatespend", { psbt: primary.signedA });
  await liana("updatespend", { psbt: primary.signedB });
  const [stored] = (await liana("listspendtxs")).spend_txs;
  primary.mergedByLiana = stored.psbt;
  primary.txid = cli("decodepsbt", spend.psbt).tx.txid;
  await liana("broadcastspend", { txid: primary.txid });
  primary.final = raw("getrawtransaction", primary.txid);
  mine(1);
  primary.blockhash = cli("getrawtransaction", primary.txid, "1").blockhash;
  if (!primary.blockhash) throw new Error("the primary spend was not mined");
  await liana("delspendtx", { txid: primary.txid });

  // 3. Recovery spend: every coin, through the 10-block path, once the last of them is 10 blocks deep.
  mine(9);
  await synced(cli("getblockcount"));
  const sweep = raw("-rpcwallet=miner", "getnewaddress");
  const recoveryCreated = await liana("createrecovery", { address: sweep, feerate: 2, timelock: 10 });
  const recovery = { unsigned: recoveryCreated.psbt, timelock: 10 };
  recovery.signedA = sign("A", recovery.unsigned);
  recovery.signedC = sign("C", recovery.unsigned);
  recovery.txid = cli("decodepsbt", recovery.unsigned).tx.txid;
  await liana("updatespend", { psbt: recovery.signedA });
  await liana("updatespend", { psbt: recovery.signedC });
  recovery.mergedByLiana = (await liana("listspendtxs", { txids: [recovery.txid] })).spend_txs[0].psbt;
  await liana("broadcastspend", { txid: recovery.txid });
  recovery.final = raw("getrawtransaction", recovery.txid);
  mine(1);
  recovery.blockhash = cli("getrawtransaction", recovery.txid, "1").blockhash;
  if (!recovery.blockhash) throw new Error("the recovery spend was not mined");

  writeFileSync(vectors, `${JSON.stringify({
    generator: "scripts/interop/liana.mjs",
    liana: lianaVersion,
    core,
    descriptor: walletDescriptor,
    keys: Object.fromEntries(Object.entries(keys).map(([name, k]) => [name, k.fp])),
    receive,
    primary,
    recovery,
  }, null, 2)}\n`);
  console.log(`wrote ${vectors.pathname}: primary ${primary.txid}, recovery ${recovery.txid}`);
} finally {
  await liana("stop").catch(() => {});
  lianad.kill();
}
