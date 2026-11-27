// Writes test/vectors/descriptors.json: multisig descriptors from Sparrow's tests and fixtures, each with its first
// receive and change addresses as Bitcoin Core derives them. Run by hand when the cases change; the unit tests read the
// JSON and need no node.
//
//   node scripts/interop/descriptors.mjs <bitcoin-cli args for a mainnet node> -- <args for a testnet node>
//   e.g. node scripts/interop/descriptors.mjs -chain=main -rpcport=18900 -datadir=/tmp/m -- -chain=test -rpcport=18910 -datadir=/tmp/t
//
// The nodes need no blocks, peers or wallet: deriveaddresses and getdescriptorinfo only.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { base58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const split = process.argv.indexOf("--");
if (split < 0) throw new Error("usage: descriptors.mjs <main node args> -- <test node args>");
const nodes = { main: process.argv.slice(2, split), test: process.argv.slice(split + 1) };
const cli = (net, ...args) => JSON.parse(execFileSync("bitcoin-cli", [...nodes[net], ...args], { encoding: "utf8" }));
const core = execFileSync("bitcoin-cli", [...nodes.main, "-version"], { encoding: "utf8" }).split("\n")[0];

const vectors = new URL("../../test/vectors/", import.meta.url);
const b58 = base58check(sha256);
/** The same key under another version: SLIP-132 Zpub (0x02aa7ed3) or Vpub (0x02575483). */
const reversion = (xpub, version) => {
  const bytes = b58.decode(xpub).slice();
  new DataView(bytes.buffer).setUint32(0, version);
  return b58.encode(bytes);
};

/** A Coldcard multisig setup file (from Sparrow's fixtures) as [fingerprint/path]xpub keys. */
function coldcard(file) {
  const text = readFileSync(new URL(`sparrow/${file}`, vectors), "utf8");
  const path = /Derivation: m\/(.*)/.exec(text)[1].replaceAll("'", "h");
  const keys = [...text.matchAll(/^([0-9A-F]{8}): ([xt]pub\w+)/gm)].map(([, fp, xpub]) => ({ fp: fp.toLowerCase(), path, xpub }));
  return { keys, threshold: Number(/Policy: (\d+) of/.exec(text)[1]) };
}

const key = (k, tail, xpub = k.xpub) => `[${k.fp}/${k.path}]${xpub}${tail}`;
const wsh = (fn, m, keys, tail, wrap, xpubOf) => {
  const inner = `wsh(${fn}(${m},${keys.map((k) => key(k, tail, xpubOf?.(k))).join(",")}))`;
  return wrap ? `sh(${inner})` : inner;
};

// drongo OutputDescriptorTest.singleSigAddressMultisigDerivation / describesMultipleAddresses (Apache-2.0).
const drongoP2wsh = [
  { fp: "1cf0bf7e", path: "48h/0h/0h/2h", xpub: "xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz" },
  { fp: "4fc1dd4a", path: "48h/0h/0h/2h", xpub: "xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj" },
];
const drongoShWsh = [
  { fp: "793cc70b", path: "48h/0h/0h/1h", xpub: "xpub6ErVmcYYHmavsMgxEcTZyzN5sqth1ZyRpFNJC26ij1wYGC2SBKYrgt9yariSbn7HLRoZUvhUhmPfsRTPrdhhGFscpPZzmch6UTdmRP1aZUj" },
  { fp: "b3118e52", path: "48h/0h/0h/1h", xpub: "xpub6Du5Jn6eYZE96ccmAc1ZTFPzdnzrvqfG4mpamDun2qZYKywoiQJMCbS3kWWMr6U3XW6s125RLsaPABWgv2yA749ieaMe67FxkTjMsbcxCch" },
  { fp: "842bd2ed", path: "48h/0h/0h/1h", xpub: "xpub6Ex81KopPkEt9hJiWHabYy8LNsSR4A7sUQoFBk9dR8XxHrr4p9HrYWN3NCf5uwfopHnQkCG7FYnZMztKbtRtbh6tzZC4xtHPbmVVxRSN7ic" },
];
const cc1 = coldcard("cc-multisig-export-1.txt"); // 2-of-4 P2WSH, mainnet
const cc2 = coldcard("cc-multisig-export-2.txt"); // 2-of-4 P2WSH-P2SH, testnet

/** [name, net, sh-wrapped, fn, threshold, keys, SLIP-132 version or null, Sparrow's own receive/0 address or null] */
const cases = [
  ["drongo 2-of-2 P2WSH (BIP 48)", "main", false, "sortedmulti", 2, drongoP2wsh, null, "bc1qrgc6p3kylfztu06ysl752gwwuekhvtfh9vr7zg43jvu60mutamcsv948ej"],
  ["drongo 2-of-3 P2SH-P2WSH (BIP 48)", "main", true, "sortedmulti", 2, drongoShWsh, null, "3MmNkJ3e67jDGNwGL7yQ886T192Bbb81zP"],
  ["Coldcard 2-of-4 P2WSH export (Sparrow fixture)", "main", false, "sortedmulti", cc1.threshold, cc1.keys, null, null],
  ["Coldcard 2-of-4 P2WSH export, multi (key order kept)", "main", false, "multi", cc1.threshold, cc1.keys, null, null],
  ["Coldcard 2-of-4 P2WSH export, SLIP-132 Zpub", "main", false, "sortedmulti", cc1.threshold, cc1.keys, 0x02aa7ed3, null],
  ["Coldcard 2-of-4 P2SH-P2WSH testnet export (Sparrow fixture)", "test", true, "sortedmulti", cc2.threshold, cc2.keys, null, null],
  ["Coldcard 2-of-4 P2SH-P2WSH testnet export, SLIP-132 Vpub", "test", true, "sortedmulti", cc2.threshold, cc2.keys, 0x02575483, null],
];

const out = [];
for (const [name, net, wrap, fn, m, keys, slip, sparrow] of cases) {
  const branch = (b) => {
    const { descriptor } = cli(net, "getdescriptorinfo", wsh(fn, m, keys, `/${b}/*`, wrap));
    return cli(net, "deriveaddresses", descriptor, "[0,1]");
  };
  const receive = branch(0);
  const change = branch(1);
  if (sparrow && receive[0] !== sparrow) throw new Error(`${name}: Core gives ${receive[0]}, Sparrow ${sparrow}`);
  const xpubOf = slip ? (k) => reversion(k.xpub, slip) : undefined;
  const forms = {
    multipath: wsh(fn, m, keys, "/<0;1>/*", wrap, xpubOf),
    lines: `${wsh(fn, m, keys, "/0/*", wrap, xpubOf)}\n${wsh(fn, m, keys, "/1/*", wrap, xpubOf)}`,
    template: wsh(fn, m, keys, "/**", wrap, xpubOf),
  };
  // Core expands <0;1> in .descriptor and keeps only /0/*; .checksum is over the text as given.
  if (!slip) forms.multipath += `#${cli(net, "getdescriptorinfo", forms.multipath).checksum}`;
  out.push({ name, network: net, forms, receive, change, sparrow });
}

const doc = {
  source: `Keys from sparrowwallet/drongo OutputDescriptorTest.java and sparrowwallet/sparrow test fixtures (Apache-2.0); addresses from ${core} deriveaddresses`,
  generated: new Date().toISOString().slice(0, 10),
  cases: out,
};
writeFileSync(new URL("descriptors.json", vectors), `${JSON.stringify(doc, null, 1)}\n`);
console.log(`wrote ${out.length} cases`);
