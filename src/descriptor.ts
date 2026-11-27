/**
 * The wallet: a multisig output descriptor (BIP 380-383), parsed here because @scure/btc-signer has no descriptor
 * parser. Only what a co-signer's coordinator exports for a multisig wallet is taken:
 *
 *   wsh(sortedmulti(k,KEY,...)), wsh(multi(k,...)), sh(wsh(...)) of either
 *   KEY = [fingerprint/origin/path]xpub/<0;1>/*   (or /** as BIP 388 and Sparrow write it, or /0/* and /1/* on two lines, as Bitcoin Core lists them)
 *
 * Every key needs its origin, as the PSBT's derivation paths are matched against it. SLIP-132 prefixes (Zpub, Vpub...)
 * are read as xpub/tpub. A `#checksum` is checked when present. The descriptor holds public keys only.
 *
 * Caravan's wallet file (JSON) is read as the descriptor it describes (caravanWallet).
 *
 * A Liana wallet is a miniscript one: wsh(MINISCRIPT), e.g. wsh(or_d(pk(A),and_v(v:pkh(B),older(N)))), each key with
 * its own <receive;change> pair (Liana puts one key on several paths with <0;1>, <2;3>...). See miniscript.ts.
 *
 * A Taproot Liana wallet is tr(INTERNAL,TREE): TREE is one Tapscript miniscript leaf or {TREE,TREE}. INTERNAL is a
 * co-signer's key (Liana's one-key primary path: a key-path spend), or an unspendable key, never shown as a co-signer:
 * BIP 341's H point, as x-only hex or as an xpub whose key is H (Liana's, its chain code taken from the tree's keys, at
 * <0;1>/*, written without an origin). Only that key may come without its origin.
 *
 * The wallet is the person's own, pasted from their coordinator: it is never taken from the contact (see docs/protocol.md).
 */
import { HDKey } from "@scure/bip32";
import { p2ms, p2sh, p2wsh, utils as btcUtils } from "@scure/btc-signer";
import { base58check, hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { compile, MiniscriptError, olderLocks, parseMiniscript, printMiniscript, spendPaths, type Miniscript, type SpendPath } from "./miniscript.ts";

export const HARDENED = 0x80000000;

/** One co-signer's key in the descriptor. */
export interface WalletKey {
  /** The master key's fingerprint, 8 hex characters, as in the descriptor's origin. */
  fingerprint: string;
  /** The origin path, from the master key to `xpub`. */
  origin: number[];
  /** The key as the descriptor gives it, normalised to xpub/tpub. */
  xpub: string;
  /** The unhardened steps after `xpub`: a number, "branch" (the receive/change step) or "index" (the `*`). */
  steps: (number | "branch" | "index")[];
  /** The branch step's value for receive and change addresses: the wallet's, or the key's own in a miniscript wallet. */
  branches: { receive: number; change: number };
  hd: HDKey;
}

export type ScriptType = "wsh" | "sh-wsh" | "tr";
export type Chain = "main" | "test";

export interface Wallet {
  script: ScriptType;
  sorted: boolean;
  /** Signatures a multisig wallet needs; for a miniscript one, its first spending path's. */
  threshold: number;
  /** The descriptor's keys in order. In a miniscript wallet one co-signer's key can be here more than once, at other paths. */
  keys: WalletKey[];
  /** A miniscript (Liana) wallet's script, its keys indexes into `keys`; absent for a multisig wallet and a Taproot one. */
  policy?: Miniscript;
  /** A Taproot (Liana) wallet's internal key and script tree. */
  taproot?: Taproot;
  /** The branch step's value for receive and change addresses; a miniscript wallet's are 0 and 1, each key's own in its `branches`. */
  branches: { receive: number; change: number };
  /** xpub (main) or tpub (test, signet, regtest). */
  chain: Chain;
  /** 16 hex characters: the same wallet gives the same id whatever way the descriptor was written. */
  id: string;
}

/** A Taproot script tree: one leaf, or a branch of two trees. */
export type TapTree = { leaf: Miniscript } | { left: TapTree; right: TapTree };

export interface Taproot {
  /** The internal key, an index into the wallet's keys (its spend is a key-path spend); null if it is unspendable. */
  internal: number | null;
  /** The unspendable internal key: an xpub whose key is H, derived as the wallet's keys are, or H itself (x-only). */
  unspendable?: WalletKey | Uint8Array;
  tree: TapTree;
  /** The tree's leaves, in the descriptor's order. */
  leaves: Miniscript[];
}

export class DescriptorError extends Error {}

const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(symbols: number[]): bigint {
  let chk = 1n;
  for (const value of symbols) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= GENERATOR[i];
  }
  return chk;
}

/** The descriptor's 8-character checksum (BIP 380), or null if it holds a character outside the descriptor charset. */
export function descriptorChecksum(text: string): string | null {
  const symbols: number[] = [];
  let groups: number[] = [];
  for (const c of text) {
    const v = INPUT_CHARSET.indexOf(c);
    if (v < 0) return null;
    symbols.push(v & 31);
    groups.push(v >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups = [];
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  const sum = polymod([...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) ^ 1n;
  let out = "";
  for (let i = 0; i < 8; i++) out += CHECKSUM_CHARSET[Number((sum >> BigInt(5 * (7 - i))) & 31n)];
  return out;
}

/** Extended-key versions: xpub, and the SLIP-132 forms read as it (main); tpub and its forms (test). */
const MAIN_VERSIONS = [0x0488b21e, 0x049d7cb2, 0x04b24746, 0x0295b43f, 0x02aa7ed3];
const TEST_VERSIONS = [0x043587cf, 0x044a5262, 0x045f1cf6, 0x024289ef, 0x02575483];
const XPUB = 0x0488b21e;
const TPUB = 0x043587cf;
const b58 = base58check(sha256);

function normaliseKey(text: string): { xpub: string; chain: Chain; hd: HDKey } {
  let bytes: Uint8Array;
  try {
    bytes = b58.decode(text);
  } catch {
    throw new DescriptorError(`not an extended public key: ${text.slice(0, 12)}…`);
  }
  if (bytes.length !== 78) throw new DescriptorError(`not an extended public key: ${text.slice(0, 12)}…`);
  const version = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  const chain: Chain | null = MAIN_VERSIONS.includes(version) ? "main" : TEST_VERSIONS.includes(version) ? "test" : null;
  if (!chain) throw new DescriptorError(`a private or unknown key: ${text.slice(0, 4)}…. Paste the descriptor with public keys only.`);
  const out = bytes.slice();
  new DataView(out.buffer).setUint32(0, chain === "main" ? XPUB : TPUB);
  const xpub = b58.encode(out);
  const versions = chain === "main" ? { private: 0x0488ade4, public: XPUB } : { private: 0x04358394, public: TPUB };
  return { xpub, chain, hd: HDKey.fromExtendedKey(xpub, versions) };
}

function pathStep(step: string): number {
  const m = /^(\d+)(['hH]?)$/.exec(step);
  if (!m) throw new DescriptorError(`not a derivation step: ${step}`);
  const n = Number(m[1]);
  if (!Number.isSafeInteger(n) || n >= HARDENED) throw new DescriptorError(`derivation step out of range: ${step}`);
  return m[2] ? n + HARDENED : n;
}

interface ParsedKey {
  fingerprint: string;
  origin: number[];
  xpub: string;
  chain: Chain;
  hd: HDKey;
  /** The steps after the key, with the receive/change step as a list of its values (one, or two for `<a;b>`). */
  steps: (number | number[] | "index")[];
}

function parseKey(raw: string, noOrigin = false): ParsedKey {
  // `/**` is BIP 388's (and Sparrow's) short form of `/<0;1>/*`.
  const text = raw.endsWith("/**") ? `${raw.slice(0, -3)}/<0;1>/*` : raw;
  const re = noOrigin
    ? /^(?:\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\])?([1-9A-HJ-NP-Za-km-z]+)((?:\/(?:[0-9]+|<[0-9]+;[0-9]+>|\*))*)$/
    : /^\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\]([1-9A-HJ-NP-Za-km-z]+)((?:\/(?:[0-9]+|<[0-9]+;[0-9]+>|\*))*)$/;
  const m = re.exec(text);
  if (!m) {
    if (!text.startsWith("[")) throw new DescriptorError("every key needs its origin, as [fingerprint/path]xpub");
    throw new DescriptorError(`a key this app cannot read: ${text.slice(0, 24)}…`);
  }
  const { xpub, chain, hd } = normaliseKey(m[3]);
  const origin = m[2] ? m[2].slice(1).split("/").map(pathStep) : [];
  if (m[1] && hd.depth !== origin.length) throw new DescriptorError(`key ${m[1].toLowerCase()}: its origin path does not match its depth`);
  const steps = m[4] ? m[4].slice(1).split("/").map((s): number | number[] | "index" => {
    if (s === "*") return "index";
    if (s.startsWith("<")) return s.slice(1, -1).split(";").map(pathStep);
    return pathStep(s);
  }) : [];
  if (steps.at(-1) !== "index" || steps.filter((s) => s === "index").length !== 1) {
    throw new DescriptorError("every key must end in /* (a ranged descriptor)");
  }
  if (steps.some((s) => typeof s === "number" && s >= HARDENED) || steps.some((s) => Array.isArray(s) && s.some((n) => n >= HARDENED))) {
    throw new DescriptorError("hardened steps after the key cannot be derived from a public key");
  }
  return { fingerprint: (m[1] ?? "").toLowerCase(), origin, xpub, chain, hd, steps };
}

interface ParsedLine {
  script: ScriptType;
  sorted: boolean;
  threshold: number;
  keys: ParsedKey[];
  policy?: Miniscript;
  taproot?: { internal: number | null; unspendable?: ParsedKey | Uint8Array; tree: TapTree; leaves: Miniscript[] };
}

function parseMiniscriptLine(script: ScriptType, body: string): ParsedLine {
  const keys: ParsedKey[] = [];
  let policy: Miniscript;
  try {
    policy = parseMiniscript(body, (text) => keys.push(parseKey(text)) - 1);
  } catch (e) {
    if (e instanceof MiniscriptError) throw new DescriptorError(`not a wallet descriptor this app can read: ${e.message}`);
    throw e;
  }
  if (!keys.length) throw new DescriptorError("the descriptor has no keys");
  if (keys.length > 64) throw new DescriptorError("too many keys");
  checkLocks(policy);
  return { script, sorted: false, threshold: firstThreshold(policy), keys, policy };
}

function checkLocks(ms: Miniscript) {
  if (olderLocks(ms).some((n) => n & 0x00400000 || n > 0xffff)) {
    throw new DescriptorError("only timelocks in blocks (up to 65535) are supported");
  }
}

function firstThreshold(policy: Miniscript): number {
  let threshold = 1;
  for (let m: Miniscript = policy; ; m = m.subs[0]) {
    if (m.f === "multi" || m.f === "multi_a" || m.f === "thresh") threshold = m.k!;
    if (m.f === "multi" || m.f === "multi_a" || m.f === "thresh" || !m.subs.length) break;
  }
  return threshold;
}

/** BIP 341's H: the x coordinate of a point no one knows the private key of. */
export const NUMS_H = hex.decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

/** Splits `a,b` at its first comma outside (), {} and []. */
function splitTop(text: string): string[] {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if ("({[".includes(c)) depth++;
    else if (")}]".includes(c)) depth--;
    else if (c === "," && depth === 0) return [text.slice(0, i), text.slice(i + 1)];
  }
  return [text];
}

/** tr(INTERNAL,TREE): the internal key (a co-signer's, or unspendable) and the tree of Tapscript leaves. */
function parseTaprootLine(body: string): ParsedLine {
  const [internalText, treeText] = splitTop(body);
  if (treeText === undefined) throw new DescriptorError("a Taproot wallet with no script leaves is a one-key wallet, not a multisig one");
  const keys: ParsedKey[] = [];
  let internal: number | null = null;
  let unspendable: ParsedKey | Uint8Array | undefined;
  if (/^(02)?[0-9a-fA-F]{64}$/.test(internalText)) {
    const x = hex.decode(internalText.slice(-64).toLowerCase());
    if (!x.every((b, i) => b === NUMS_H[i])) throw new DescriptorError("the internal key is a bare public key: give it as [fingerprint/path]xpub/<0;1>/*");
    unspendable = x;
  } else {
    const k = parseKey(internalText, true);
    if (k.hd.publicKey![0] === 0x02 && k.hd.publicKey!.subarray(1).every((b, i) => b === NUMS_H[i])) unspendable = k;
    else if (!k.fingerprint) throw new DescriptorError("every key needs its origin, as [fingerprint/path]xpub");
    else internal = keys.push(k) - 1;
  }
  const leaves: Miniscript[] = [];
  const tree = (text: string, depth: number): TapTree => {
    if (depth > 128) throw new DescriptorError("the Taproot tree is too deep");
    if (text.startsWith("{")) {
      if (!text.endsWith("}")) throw new DescriptorError("the Taproot tree's braces do not match");
      const parts = splitTop(text.slice(1, -1));
      if (parts.length !== 2) throw new DescriptorError("a branch of the Taproot tree, {A,B}, holds two trees");
      return { left: tree(parts[0], depth + 1), right: tree(parts[1], depth + 1) };
    }
    let ms: Miniscript;
    try {
      ms = parseMiniscript(text, (t) => keys.push(parseKey(t)) - 1, true);
    } catch (e) {
      if (e instanceof MiniscriptError) throw new DescriptorError(`not a wallet descriptor this app can read: ${e.message}`);
      throw e;
    }
    checkLocks(ms);
    leaves.push(ms);
    return { leaf: ms };
  };
  const t = tree(treeText, 0);
  if (keys.length > 64) throw new DescriptorError("too many keys");
  const threshold = internal !== null ? 1 : firstThreshold(leaves[0]);
  return { script: "tr", sorted: false, threshold, keys, taproot: { internal, unspendable, tree: t, leaves } };
}

function parseLine(raw: string): ParsedLine {
  let text = raw.trim();
  const hash = text.lastIndexOf("#");
  if (hash >= 0) {
    const given = text.slice(hash + 1);
    text = text.slice(0, hash);
    if (descriptorChecksum(text) !== given) throw new DescriptorError("the descriptor's checksum does not match: it was changed or cut");
  }
  text = text.replace(/\s+/g, "");
  let script: ScriptType = "wsh";
  let body: string;
  const sh = /^sh\(wsh\((.*)\)\)$/.exec(text);
  const wsh = /^wsh\((.*)\)$/.exec(text);
  if (sh) {
    script = "sh-wsh";
    body = sh[1];
  } else if (wsh) {
    body = wsh[1];
  } else if (/^tr\(.*\)$/.test(text)) {
    return parseTaprootLine(text.slice(3, -1));
  } else {
    throw new DescriptorError("only wsh(...), sh(wsh(...)) and Taproot Liana tr(...) descriptors are supported");
  }
  const ms = /^(sortedmulti|multi)\((\d+),([^()]*)\)$/.exec(body);
  if (!ms) {
    if (/^sortedmulti\(/.test(body)) throw new DescriptorError("not a multisig descriptor: expected sortedmulti(k,KEY,...)");
    return parseMiniscriptLine(script, body);
  }
  const threshold = Number(ms[2]);
  const keys = ms[3].split(",").map((k) => parseKey(k));
  if (keys.length < 2 || keys.length > 15) throw new DescriptorError("a multisig wallet has 2 to 15 keys");
  if (threshold < 1 || threshold > keys.length) throw new DescriptorError(`threshold ${threshold} of ${keys.length} keys is not possible`);
  return { script, sorted: ms[1] === "sortedmulti", threshold, keys };
}

/** The wallet from a pasted descriptor: one line with `<0;1>`, or two lines (receive /0/*, change /1/*). Lines starting with `#` are comments. */
/**
 * Caravan's wallet file ("Download wallet details"): its quorum, address type and keys, each with `xfp` and
 * `bip32Path`. Caravan sorts the keys (BIP 67) and derives receive from branch 0, change from branch 1, so the file
 * is the descriptor `sortedmulti(k, [xfp/path]xpub/<0;1>/*, ...)`. Null when the text is not a JSON object.
 */
export function caravanWallet(input: string): { descriptor: string; network: "main" | "test" | "regtest" } | null {
  const text = input.trim();
  if (!text.startsWith("{")) return null;
  let c: unknown;
  try {
    c = JSON.parse(text);
  } catch {
    throw new DescriptorError("not a wallet file this app can read: paste the output descriptor or Caravan's wallet file");
  }
  const o = c as { addressType?: unknown; network?: unknown; quorum?: { requiredSigners?: unknown; totalSigners?: unknown }; extendedPublicKeys?: unknown };
  if (!Array.isArray(o.extendedPublicKeys) || typeof o.quorum !== "object" || o.quorum === null) {
    throw new DescriptorError("not a Caravan wallet file: it has no quorum and extendedPublicKeys");
  }
  const wrap = o.addressType === "P2WSH" ? (m: string) => `wsh(${m})` : o.addressType === "P2SH-P2WSH" ? (m: string) => `sh(wsh(${m}))` : null;
  if (!wrap) throw new DescriptorError(`Caravan ${String(o.addressType)} wallets are not supported: only P2WSH and P2SH-P2WSH`);
  const network = ({ mainnet: "main", testnet: "test", signet: "test", regtest: "regtest" } as const)[String(o.network) as "mainnet"];
  if (!network) throw new DescriptorError(`a Caravan wallet on an unknown network: ${String(o.network)}`);
  const keys = (o.extendedPublicKeys as { name?: unknown; xfp?: unknown; bip32Path?: unknown; xpub?: unknown }[]).map((k, n) => {
    const who = typeof k.name === "string" && k.name ? `"${k.name}"` : `${n + 1}`;
    const xfp = typeof k.xfp === "string" ? k.xfp.toLowerCase() : "";
    const path = typeof k.bip32Path === "string" ? k.bip32Path : "";
    if (!/^[0-9a-f]{8}$/.test(xfp) || !/^m(\/\d+['h]?)*$/.test(path)) {
      throw new DescriptorError(`key ${who} has no fingerprint and path in the Caravan file: add them in Caravan, then download the file again`);
    }
    if (typeof k.xpub !== "string") throw new DescriptorError(`key ${who} has no xpub in the Caravan file`);
    return `[${xfp}${path.slice(1).replaceAll("'", "h")}]${k.xpub}/<0;1>/*`;
  });
  if (o.quorum.totalSigners !== keys.length) throw new DescriptorError("the Caravan file's quorum does not match its keys");
  const threshold = o.quorum.requiredSigners;
  if (!Number.isSafeInteger(threshold)) throw new DescriptorError("the Caravan file has no number of required signers");
  return { descriptor: wrap(`sortedmulti(${threshold as number},${keys.join(",")})`), network };
}

export function parseWallet(input: string): Wallet {
  const caravan = caravanWallet(input);
  if (caravan) return parseWallet(caravan.descriptor);
  const lines = input.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.length === 0) throw new DescriptorError("paste the wallet's output descriptor");
  if (lines.length > 2) throw new DescriptorError("paste one descriptor (or its receive and change lines)");
  const parsed = lines.map(parseLine);
  const first = parsed[0];
  if (first.policy || parsed[1]?.policy || first.taproot || parsed[1]?.taproot) {
    if (parsed.length === 2) throw new DescriptorError("paste a miniscript wallet as one descriptor, with <receive;change> steps");
    return miniscriptWallet(first);
  }
  const shape = (p: ParsedLine) => JSON.stringify([p.script, p.sorted, p.threshold, p.keys.map((k) => [k.fingerprint, k.origin, k.xpub, k.steps.length])]);
  if (parsed.length === 2 && shape(parsed[0]) !== shape(parsed[1])) throw new DescriptorError("the two lines are not the same wallet");
  // The step whose value differs between receive and change: a <a;b> step, or the one that differs between the lines.
  const stepCount = first.keys[0].steps.length;
  if (first.keys.some((k) => k.steps.length !== stepCount)) throw new DescriptorError("the keys' paths after the xpub differ in length");
  let branchAt = -1;
  let receive = 0;
  let change = 1;
  for (let i = 0; i < stepCount; i++) {
    const values = parsed.flatMap((p) => p.keys.map((k) => k.steps[i]));
    if (values.some(Array.isArray)) {
      if (!values.every((v) => Array.isArray(v) && v.length === 2 && v[0] === (values[0] as number[])[0] && v[1] === (values[0] as number[])[1])) {
        throw new DescriptorError("the keys' <receive;change> steps differ");
      }
      if (parsed.length === 2) throw new DescriptorError("a <receive;change> step is for one line only");
      [receive, change] = values[0] as number[];
      branchAt = i;
    } else if (new Set(values.map(String)).size > 1) {
      // Two lines: every key's step i is the same within a line, and the lines differ.
      const perLine = parsed.map((p) => new Set(p.keys.map((k) => String(k.steps[i]))));
      if (parsed.length !== 2 || perLine.some((s) => s.size !== 1)) throw new DescriptorError("the keys' paths after the xpub differ");
      receive = parsed[0].keys[0].steps[i] as number;
      change = parsed[1].keys[0].steps[i] as number;
      branchAt = i;
    }
  }
  if (branchAt < 0) {
    if (parsed.length === 2) throw new DescriptorError("the two lines are the same descriptor");
    throw new DescriptorError("the descriptor has no change addresses: use /<0;1>/* or paste the /0/* and /1/* lines");
  }
  if (receive === change) throw new DescriptorError("receive and change are the same branch");
  const chains = new Set(first.keys.map((k) => k.chain));
  if (chains.size !== 1) throw new DescriptorError("the keys mix mainnet (xpub) and test (tpub) keys");
  const keys: WalletKey[] = first.keys.map((k) => ({
    fingerprint: k.fingerprint,
    origin: k.origin,
    xpub: k.xpub,
    hd: k.hd,
    steps: k.steps.map((s, i) => (i === branchAt ? "branch" : s)) as WalletKey["steps"],
    branches: { receive, change },
  }));
  if (new Set(keys.map((k) => k.xpub)).size !== keys.length) throw new DescriptorError("the same key is in the wallet twice");
  const canonical = [
    first.script,
    first.sorted ? "sorted" : "multi",
    first.threshold,
    receive,
    change,
    ...(first.sorted ? [...keys].sort((a, b) => (a.xpub < b.xpub ? -1 : 1)) : keys).map(
      (k) => `${k.fingerprint}/${k.origin.join("/")}/${k.xpub}/${k.steps.join("/")}`,
    ),
  ].join("|");
  const id = hex.encode(sha256(new TextEncoder().encode(canonical))).slice(0, 16);
  return { script: first.script, sorted: first.sorted, threshold: first.threshold, keys, branches: { receive, change }, chain: [...chains][0], id };
}

/** A miniscript (Liana) wallet, P2WSH or Taproot: every key with its own <receive;change> step. */
function miniscriptWallet(line: ParsedLine): Wallet {
  const numsKey = line.taproot?.unspendable instanceof Uint8Array ? undefined : line.taproot?.unspendable;
  const chains = new Set([...line.keys, ...(numsKey ? [numsKey] : [])].map((k) => k.chain));
  if (chains.size !== 1) throw new DescriptorError("the keys mix mainnet (xpub) and test (tpub) keys");
  const walletKey = (k: ParsedKey): WalletKey => {
    const multi = k.steps.filter(Array.isArray);
    if (multi.length !== 1 || multi[0].length !== 2) {
      throw new DescriptorError(`key ${k.fingerprint}: every key needs one <receive;change> step, as /<0;1>/*`);
    }
    const [receive, change] = multi[0];
    if (receive === change) throw new DescriptorError("receive and change are the same branch");
    return {
      fingerprint: k.fingerprint,
      origin: k.origin,
      xpub: k.xpub,
      hd: k.hd,
      steps: k.steps.map((s) => (Array.isArray(s) ? "branch" : s)) as WalletKey["steps"],
      branches: { receive, change },
    };
  };
  const keys = line.keys.map(walletKey);
  // One key on several paths is fine, at other steps; the same public key twice is not.
  const paths = keys.flatMap((k) =>
    [k.branches.receive, k.branches.change].map((b) => `${k.xpub}/${k.steps.map((s) => (s === "branch" ? b : s)).join("/")}`),
  );
  if (new Set(paths).size !== paths.length) throw new DescriptorError("the same key is in the wallet twice");
  const printKey = (k: WalletKey) => `${k.fingerprint}/${k.origin.join("/")}/${k.xpub}/${k.steps.join("/")}/${k.branches.receive};${k.branches.change}`;
  const print = (ms: Miniscript) => printMiniscript(ms, (i) => printKey(keys[i]));
  const base = { script: line.script, sorted: false, threshold: line.threshold, keys, branches: { receive: 0, change: 1 }, chain: [...chains][0] };
  const idOf = (canonical: string[]) => hex.encode(sha256(new TextEncoder().encode(canonical.join("|")))).slice(0, 16);
  if (line.taproot) {
    const t = line.taproot;
    const unspendable = t.unspendable instanceof Uint8Array ? t.unspendable : t.unspendable && walletKey(t.unspendable);
    const printTree = (tree: TapTree): string => ("leaf" in tree ? print(tree.leaf) : `{${printTree(tree.left)},${printTree(tree.right)}}`);
    // The unspendable key's origin, if written, is no one's: it is left out.
    const nums = (k: WalletKey) => `${k.xpub}/${k.steps.join("/")}/${k.branches.receive};${k.branches.change}`;
    const internal = t.internal !== null ? `key:${t.internal}` : unspendable instanceof Uint8Array ? "nums" : `nums:${nums(unspendable!)}`;
    const id = idOf(["tr", internal, printTree(t.tree)]);
    return { ...base, taproot: { internal: t.internal, unspendable, tree: t.tree, leaves: t.leaves }, id };
  }
  const policy = line.policy!;
  return { ...base, policy, id: idOf([line.script, "miniscript", print(policy)]) };
}

function deriveKey(wallet: Wallet, key: WalletKey, branch: number, index: number): Uint8Array {
  // The wallet's receive or change branch, as this key has it.
  const own = branch === wallet.branches.receive ? key.branches.receive : branch === wallet.branches.change ? key.branches.change : branch;
  let node = key.hd;
  for (const step of key.steps) node = node.deriveChild(step === "branch" ? own : step === "index" ? index : step);
  if (!node.publicKey) throw new DescriptorError("could not derive a public key");
  return node.publicKey;
}

/** The public keys of the wallet's address at (branch, index), in the descriptor's key order. */
export function derivePubkeys(wallet: Wallet, branch: number, index: number): Uint8Array[] {
  return wallet.keys.map((key) => deriveKey(wallet, key, branch, index));
}

/** One script leaf of a Taproot address. */
export interface TapLeaf {
  ms: Miniscript;
  script: Uint8Array;
  leafHash: Uint8Array;
  /** BIP 341's control block: leaf version and parity, the internal key, the hashes up the tree. */
  controlBlock: Uint8Array;
}

export interface TaprootAddress {
  /** The output script, OP_1 <32-byte key>. */
  script: Uint8Array;
  /** The internal key, x-only. */
  internal: Uint8Array;
  /** True if the internal key is a co-signer's: the address can be spent by the key path. */
  keyPath: boolean;
  /** The wallet's keys at this address, x-only, in the descriptor's order. */
  xonly: Uint8Array[];
  merkleRoot: Uint8Array;
  /** The leaves, in the descriptor's order. */
  leaves: TapLeaf[];
}

export const TAPSCRIPT_LEAF = 0xc0;
const tagged = schnorr.utils.taggedHash;

function compactSize(n: number): number[] {
  return n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8];
}

/** BIP 341's leaf hash of a Tapscript leaf. */
export const tapLeafHash = (script: Uint8Array): Uint8Array =>
  tagged("TapLeaf", Uint8Array.of(TAPSCRIPT_LEAF, ...compactSize(script.length)), script);

/** BIP 341's hash of a tree branch: its two children's hashes, the smaller first. */
export const tapBranch = (a: Uint8Array, b: Uint8Array): Uint8Array =>
  compare(a, b) <= 0 ? tagged("TapBranch", a, b) : tagged("TapBranch", b, a);

/** The Taproot address at (branch, index): its key, its leaves with their control blocks. */
export function deriveTaproot(wallet: Wallet, branch: number, index: number): TaprootAddress {
  const t = wallet.taproot;
  if (!t) throw new DescriptorError("not a Taproot wallet");
  const xonly = derivePubkeys(wallet, branch, index).map((p) => p.subarray(1));
  const internal = t.internal !== null ? xonly[t.internal]
    : t.unspendable instanceof Uint8Array ? t.unspendable
    : deriveKey(wallet, t.unspendable!, branch, index).subarray(1);
  const scripts = t.leaves.map((ms) => compile(ms, xonly));
  const hashes = scripts.map(tapLeafHash);
  const paths: Uint8Array[][] = scripts.map(() => []);
  let next = 0;
  // Each leaf's path: its siblings' hashes, from the leaf up to the root.
  const walk = (tree: TapTree): { hash: Uint8Array; leaves: number[] } => {
    if ("leaf" in tree) {
      const i = next++;
      return { hash: hashes[i], leaves: [i] };
    }
    const l = walk(tree.left);
    const r = walk(tree.right);
    for (const i of l.leaves) paths[i].push(r.hash);
    for (const i of r.leaves) paths[i].push(l.hash);
    return { hash: tapBranch(l.hash, r.hash), leaves: [...l.leaves, ...r.leaves] };
  };
  const merkleRoot = walk(t.tree).hash;
  const [q, parity] = btcUtils.taprootTweakPubkey(internal, merkleRoot);
  const leaves = t.leaves.map((ms, i) => ({
    ms,
    script: scripts[i],
    leafHash: hashes[i],
    controlBlock: Uint8Array.from([TAPSCRIPT_LEAF | parity, ...internal, ...paths[i].flatMap((h) => [...h])]),
  }));
  return { script: Uint8Array.of(0x51, 0x20, ...q), internal, keyPath: t.internal !== null, xonly, merkleRoot, leaves };
}

/** The ways to spend from the wallet: a Taproot wallet's key path, if it has one, then its leaves'. */
export function walletSpendPaths(w: Wallet): SpendPath[] {
  if (!w.taproot) return spendPaths(w.policy!);
  const key: SpendPath[] = w.taproot.internal !== null ? [{ groups: [{ k: 1, keys: [w.taproot.internal] }], older: [], after: [] }] : [];
  return [...key, ...w.taproot.leaves.flatMap(spendPaths)];
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** The wallet's output script and witness script at (branch, index). */
export function deriveScript(wallet: Wallet, branch: number, index: number): { script: Uint8Array; witnessScript: Uint8Array } {
  // A Taproot address has no one witness script: see deriveTaproot.
  if (wallet.taproot) return { script: deriveTaproot(wallet, branch, index).script, witnessScript: new Uint8Array() };
  let pubkeys = derivePubkeys(wallet, branch, index);
  if (wallet.policy) {
    const witnessScript = compile(wallet.policy, pubkeys);
    const wsh = p2wsh({ type: "unknown", script: witnessScript } as never);
    return { script: wallet.script === "wsh" ? wsh.script : p2sh(wsh).script, witnessScript };
  }
  if (wallet.sorted) pubkeys = [...pubkeys].sort(compare);
  const ms = p2ms(wallet.threshold, pubkeys);
  const wsh = p2wsh(ms);
  if (wallet.script === "wsh") return { script: wsh.script, witnessScript: ms.script };
  return { script: p2sh(wsh).script, witnessScript: ms.script };
}

/** `a-b-c` key labels: each key's fingerprint, the way coordinators show them. */
export const fingerprints = (wallet: Wallet): string[] => [...new Set(wallet.keys.map((k) => k.fingerprint))];

/**
 * The wallet as Coldcard's multisig setup file, the text Passport, Keystone and Coldcard import (Keystone and Passport
 * by scanning it as a `ur:bytes` QR). Those devices take only sorted keys on branches 0 and 1, so other wallets throw.
 */
export function coldcardFile(w: Wallet): string {
  if (w.policy || w.taproot) throw new DescriptorError("hardware wallets import a Liana wallet from Liana itself, not as a multisig file");
  if (!w.sorted) throw new DescriptorError("hardware wallets import only sortedmulti wallets, and this one is multi");
  if (w.branches.receive !== 0 || w.branches.change !== 1 || w.keys.some((k) => k.steps.join() !== "branch,index")) {
    throw new DescriptorError("hardware wallets import only wallets whose keys end in /<0;1>/*");
  }
  const path = (origin: number[]) => ["m", ...origin.map((n) => (n >= HARDENED ? `${n - HARDENED}'` : String(n)))].join("/");
  const lines = [
    "# Multisig setup file (Coldcard format), from Ghostly Multisig",
    `Name: ghostly-${w.id.slice(0, 8)}`,
    `Policy: ${w.threshold} of ${w.keys.length}`,
    `Format: ${w.script === "wsh" ? "P2WSH" : "P2WSH-P2SH"}`,
  ];
  for (const k of w.keys) lines.push("", `Derivation: ${path(k.origin)}`, `${k.fingerprint.toUpperCase()}: ${k.xpub}`);
  return `${lines.join("\n")}\n`;
}
