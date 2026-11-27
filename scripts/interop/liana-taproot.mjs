// Writes test/vectors/liana-taproot.json: two Taproot Liana wallets on regtest, each run by Liana's own daemon
// (lianad), with Bitcoin Core as the node and as each co-signer's signer. The sibling of liana.mjs (P2WSH).
//
// "nums": a multi-key primary path, so the internal key is unspendable: Liana's own NUMS-derived xpub (BIP 341's H
// point, its chain code the sha256 of the tree's keys, as liana/src/descriptors/analysis.rs makes it), at <0;1>/*.
//   primary:               multi_a(2, A, B)                          (leaf at depth 1)
//   recovery after 10:     multi_a(2, A at <2;3>, C)                 (depth 2)
//   recovery after 20:     multi_a(2, A, B, C, all at <4;5>)         (depth 2)
// "keypath": Liana's simplest shape, one primary key and one recovery key: the primary key is the internal key, and
// its spend is a key-path spend (a Schnorr signature alone).
//   primary:               A (key path)
//   recovery after 10:     pk(B)
//
// For each wallet:
//   1. lianad hands out two receive addresses (and lists its receive and change addresses); Core funds them.
//   2. Primary spend: lianad creates it (createspend, with change); the primary co-signers (Core wallets) sign it apart;
//      lianad merges them (updatespend), finalises and broadcasts it (broadcastspend). Core mines it.
//   3. Recovery spend: 10 blocks are mined; lianad sweeps every coin through the 10-block path (createrecovery); the
//      recovery co-signers sign apart; lianad merges, finalises and broadcasts; Core mines it.
// The unit tests (test/unit/liana-taproot.test.ts) check the app against all of it.
//
//   node scripts/interop/liana-taproot.mjs <folder with lianad> <work folder> <bitcoin-cli args for a fresh regtest node>
//
// The node needs -fallbackfee=0.0001 and -txindex=1. Liana 16.0's release binary, checked as for liana.mjs. The keys
// are the fixed test seeds liana.mjs uses (32 bytes of 0x1a, 0x1b, 0x1c): never send real coins to them. The vectors
// hold only their xpubs.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { join, resolve } from "node:path";
import { HDKey } from "@scure/bip32";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58check, hex } from "@scure/base";

const [lianaDir, workArg, ...node] = process.argv.slice(2);
if (!node.length) throw new Error("usage: liana-taproot.mjs <folder with lianad> <work folder> <bitcoin-cli args>");
const arg = (name) => node.find((a) => a.startsWith(`-${name}=`))?.slice(name.length + 2);
const rpcport = arg("rpcport");
const datadir = arg("datadir");
if (!rpcport || !datadir) throw new Error("give the node's -rpcport and -datadir: lianad needs them");
const work = resolve(workArg);
const vectors = new URL("../../test/vectors/liana-taproot.json", import.meta.url);

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
    return [name, { fp: fpOf(master), point: account.publicKey, pub: `${origin}${account.publicExtendedKey}`, prv: `${origin}${account.privateExtendedKey}` }];
  }),
);

// Liana's unspendable internal key: an xpub whose key is BIP 341's H, its chain code the sha256 of the tree's keys
// (each xpub's 33-byte key, in the tree's order, repeats included), depth 0, no parent, at <0;1>/*.
const NUMS = hex.decode("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
function numsXpub(treeKeys) {
  const concat = new Uint8Array(treeKeys.flatMap((n) => [...keys[n].point]));
  const out = new Uint8Array(78);
  const view = new DataView(out.buffer);
  view.setUint32(0, TEST.public);
  out.set(sha256(concat), 13);
  out.set(NUMS, 45);
  return base58check(sha256).encode(out);
}

// Each wallet: its descriptor (with `signer`'s keys private, or all public), who signs each spend.
const k = (signer, name, pair) => `${name === signer ? keys[name].prv : keys[name].pub}/<${pair}>/*`;
const WALLETS = {
  nums: {
    // Tree order: primary, then the 10-block and the 20-block leaves.
    treeKeys: ["A", "B", "A", "C", "A", "B", "C"],
    descriptor(signer) {
      const leaves = [
        `multi_a(2,${k(signer, "A", "0;1")},${k(signer, "B", "0;1")})`,
        `and_v(v:multi_a(2,${k(signer, "A", "2;3")},${k(signer, "C", "0;1")}),older(10))`,
        `and_v(v:multi_a(2,${k(signer, "A", "4;5")},${k(signer, "B", "4;5")},${k(signer, "C", "4;5")}),older(20))`,
      ];
      return `tr(${numsXpub(this.treeKeys)}/<0;1>/*,{${leaves[0]},{${leaves[1]},${leaves[2]}}})`;
    },
    primary: ["A", "B"],
    recovery: ["A", "C"],
  },
  keypath: {
    descriptor(signer) {
      return `tr(${k(signer, "A", "0;1")},and_v(v:pk(${k(signer, "B", "0;1")}),older(10)))`;
    },
    primary: ["A"],
    recovery: ["B"],
  },
};

let rpcId = 0;
function lianaRpc(socketPath) {
  return (method, params = {}) =>
    new Promise((ok, fail) => {
      const socket = connect(socketPath);
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

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });
process.chdir(work);
const version = spawnSync(join(lianaDir, "lianad"), ["--version"], { encoding: "utf8" });
const lianaVersion = `lianad ${(version.stdout || version.stderr).trim().split("\n")[0]}`;
const core = raw("-version").split("\n")[0];
raw("createwallet", "miner");
const mine = (n) => raw("generatetoaddress", String(n), raw("-rpcwallet=miner", "getnewaddress"));
mine(101);

async function run(name, spec) {
  // lianad's socket path must be short (SUN_LEN): a relative data dir, run in the work folder.
  mkdirSync(join(work, name), { recursive: true });
  const walletDescriptor = withSum(spec.descriptor(null));
  writeFileSync(join(work, `${name}.toml`), [
    `data_dir = "${name}"`,
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
  const lianad = spawn(join(lianaDir, "lianad"), ["--conf", `${name}.toml`], { cwd: work, stdio: ["ignore", "ignore", "inherit"] });
  const liana = lianaRpc(`${name}/regtest/lianad_rpc`);
  try {
    await until(`${name}: lianad's socket`, () => liana("getinfo"));
    // One Core wallet per co-signer, holding that co-signer's private keys in the wallet's descriptor.
    const signers = [...new Set([...spec.primary, ...spec.recovery])];
    for (const who of signers) {
      raw("-named", "createwallet", `wallet_name=${name}${who}`, "blank=true");
      const [imported] = wallet(`${name}${who}`)("importdescriptors", JSON.stringify([{ desc: withSum(spec.descriptor(who)), timestamp: "now", active: false }]));
      if (!imported.success) throw new Error(`Core did not import ${who}'s descriptor: ${JSON.stringify(imported)}`);
    }
    const sign = (who, psbt) => {
      const out = wallet(`${name}${who}`)("-named", "walletprocesspsbt", `psbt=${psbt}`, "sign=true", "finalize=false");
      if (out.psbt === psbt) throw new Error(`Core's key ${who} added no signature`);
      return out.psbt;
    };
    const synced = (height) => until(`lianad at height ${height}`, async () => (await liana("getinfo")).block_height >= height);
    await synced(cli("getblockcount"));

    // 1. Funds.
    const receive = [];
    for (let i = 0; i < 2; i++) receive.push((await liana("getnewaddress")).address);
    for (const [i, address] of receive.entries()) raw("-rpcwallet=miner", "sendtoaddress", address, i ? "0.3" : "0.5");
    mine(1);
    await synced(cli("getblockcount"));
    await until(`${name}: lianad's two coins`, async () => (await liana("listcoins")).coins.filter((c) => c.block_height).length === 2);
    const coins = (await liana("listcoins")).coins;
    const addresses = (await liana("listaddresses", { start_index: 0, count: 3 })).addresses;

    // 2. Primary spend: one coin, part of it out, the rest back as change.
    const primaryCoin = coins.find((c) => c.amount === 50_000_000);
    const external = raw("-rpcwallet=miner", "getnewaddress");
    const spend = await liana("createspend", { destinations: { [external]: 20_000_000 }, outpoints: [primaryCoin.outpoint], feerate: 2 });
    const primary = { unsigned: spend.psbt, signed: {} };
    for (const who of spec.primary) primary.signed[who] = sign(who, spend.psbt);
    for (const who of spec.primary) await liana("updatespend", { psbt: primary.signed[who] });
    primary.txid = cli("decodepsbt", spend.psbt).tx.txid;
    primary.mergedByLiana = (await liana("listspendtxs", { txids: [primary.txid] })).spend_txs[0].psbt;
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
    const created = await liana("createrecovery", { address: sweep, feerate: 2, timelock: 10 });
    const recovery = { unsigned: created.psbt, timelock: 10, signed: {} };
    for (const who of spec.recovery) recovery.signed[who] = sign(who, recovery.unsigned);
    recovery.txid = cli("decodepsbt", recovery.unsigned).tx.txid;
    for (const who of spec.recovery) await liana("updatespend", { psbt: recovery.signed[who] });
    recovery.mergedByLiana = (await liana("listspendtxs", { txids: [recovery.txid] })).spend_txs[0].psbt;
    await liana("broadcastspend", { txid: recovery.txid });
    recovery.final = raw("getrawtransaction", recovery.txid);
    mine(1);
    recovery.blockhash = cli("getrawtransaction", recovery.txid, "1").blockhash;
    if (!recovery.blockhash) throw new Error("the recovery spend was not mined");
    console.log(`${name}: primary ${primary.txid}, recovery ${recovery.txid}`);
    return { descriptor: walletDescriptor, receive, addresses, primary, recovery };
  } finally {
    await liana("stop").catch(() => {});
    lianad.kill();
  }
}

const out = { generator: "scripts/interop/liana-taproot.mjs", liana: lianaVersion, core, keys: Object.fromEntries(Object.entries(keys).map(([n, x]) => [n, x.fp])) };
for (const [name, spec] of Object.entries(WALLETS)) out[name] = await run(name, spec);
writeFileSync(vectors, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${vectors.pathname}`);
