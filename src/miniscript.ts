/**
 * The miniscript a Liana wallet's descriptor holds (wsh(or_d(pk(A),and_v(v:pkh(B),older(N)))) and its multi-key,
 * multi-path forms), for P2WSH and for Taproot's script leaves (Tapscript, BIP 342): parsed, type-checked, compiled to its witness script, read as spending paths,
 * and satisfied from the signatures a PSBT holds. Written here, not taken from a package: the subset is small, and
 * the one package (@bitcoinerlab/miniscript) gives assembly text rather than bytes and ships without a license file.
 *
 * The fragments are BIP 379's: 0 1 pk_k pk_h pk pkh older after thresh and_v and_b andor or_b or_c or_d or_i, the
 * wrappers a s c d v j n t l u, and multi in P2WSH or multi_a in Tapscript (each is refused in the other). Hash locks
 * (sha256, hash160...) and sortedmulti_a are refused. In Tapscript keys are x-only (32 bytes).
 * Types are checked as BIP 379 has them (base type B/V/K/W and the d and u properties), so a descriptor whose script
 * could not be spent, or not be dissatisfied where its parent needs it, is refused rather than read.
 *
 * A script interpreter for the same opcodes (runWitness) checks a finalised witness against its script, under segwit
 * v0's rules or Tapscript's (OP_CHECKSIGADD, no OP_CHECKMULTISIG).
 */
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";

export class MiniscriptError extends Error {}

export type Fragment =
  | "0" | "1" | "pk_k" | "pk_h" | "older" | "after" | "multi" | "multi_a" | "thresh"
  | "and_v" | "and_b" | "andor" | "or_b" | "or_c" | "or_d" | "or_i"
  | "a" | "s" | "c" | "d" | "v" | "j" | "n";

/** A miniscript node. Keys are indexes into the wallet's key list. */
export interface Miniscript {
  f: Fragment;
  subs: Miniscript[];
  /** multi, multi_a, thresh: the threshold. */
  k?: number;
  /** pk_k, pk_h: one key; multi, multi_a: their keys. */
  keys?: number[];
  /** older, after: the timelock. */
  n?: number;
}

const WRAPPERS = "asctdvjnlu";

/** Splits `a,b(c,d),e` at its top-level commas. */
function args(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      out.push(text.slice(start, i));
      start = i + 1;
    }
    if (depth < 0) throw new MiniscriptError("unbalanced parentheses");
  }
  if (depth !== 0) throw new MiniscriptError("unbalanced parentheses");
  out.push(text.slice(start));
  return out;
}

function integer(text: string, min: number, max: number, what: string): number {
  if (!/^[0-9]+$/.test(text)) throw new MiniscriptError(`${what}: not a number: ${text}`);
  const n = Number(text);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new MiniscriptError(`${what} out of range: ${text}`);
  return n;
}

const node = (f: Fragment, subs: Miniscript[] = [], extra: Partial<Miniscript> = {}): Miniscript => ({ f, subs, ...extra });

/** Parses a miniscript expression, for P2WSH or (`tap`) a Tapscript leaf; `key` reads each key expression and gives its index. */
export function parseMiniscript(text: string, key: (text: string) => number, tap = false): Miniscript {
  const ms = parseExpr(text, key, tap);
  const t = typeOf(ms, tap);
  if (t.base !== "B") throw new MiniscriptError("the miniscript is not a complete script (its top is not of type B)");
  return ms;
}

function parseExpr(text: string, key: (text: string) => number, tap: boolean): Miniscript {
  const m = /^(?:([a-z]+):)?([a-z_0-9]+)(?:\((.*)\))?$/s.exec(text);
  if (!m) throw new MiniscriptError(`not a miniscript expression: ${text.slice(0, 32)}`);
  const [, wrappers = "", name, inner] = m;
  for (const w of wrappers) if (!WRAPPERS.includes(w)) throw new MiniscriptError(`unknown wrapper ${w}:`);
  let ms = fragment(name, inner, key, tap);
  for (const w of [...wrappers].reverse()) {
    if (w === "t") ms = node("and_v", [ms, node("1")]);
    else if (w === "l") ms = node("or_i", [node("0"), ms]);
    else if (w === "u") ms = node("or_i", [ms, node("0")]);
    else ms = node(w as Fragment, [ms]);
  }
  return ms;
}

function fragment(name: string, inner: string | undefined, key: (text: string) => number, tap: boolean): Miniscript {
  const a = inner === undefined ? [] : args(inner);
  const want = (n: number) => {
    if (a.length !== n) throw new MiniscriptError(`${name} takes ${n} argument${n === 1 ? "" : "s"}`);
  };
  const sub = (i: number) => parseExpr(a[i], key, tap);
  switch (name) {
    case "0":
    case "1":
      if (inner !== undefined) throw new MiniscriptError(`${name} takes no arguments`);
      return node(name);
    case "pk_k":
    case "pk_h":
      want(1);
      return node(name, [], { keys: [key(a[0])] });
    case "pk":
    case "pkh":
      want(1);
      return node("c", [node(name === "pk" ? "pk_k" : "pk_h", [], { keys: [key(a[0])] })]);
    case "older":
    case "after":
      want(1);
      return node(name, [], { n: integer(a[0], 1, 0x7fffffff, name) });
    case "multi": {
      if (tap) throw new MiniscriptError("multi is for P2WSH: in Taproot it is multi_a");
      if (a.length < 2) throw new MiniscriptError("multi takes a threshold and keys");
      const keys = a.slice(1).map(key);
      if (keys.length > 20) throw new MiniscriptError("multi takes at most 20 keys");
      return node("multi", [], { k: integer(a[0], 1, keys.length, "multi's threshold"), keys });
    }
    case "thresh": {
      if (a.length < 2) throw new MiniscriptError("thresh takes a threshold and sub-expressions");
      const subs = a.slice(1).map((_, i) => sub(i + 1));
      return node("thresh", subs, { k: integer(a[0], 1, subs.length, "thresh's threshold") });
    }
    case "and_v":
    case "and_b":
    case "or_b":
    case "or_c":
    case "or_d":
    case "or_i":
      want(2);
      return node(name, [sub(0), sub(1)]);
    case "andor":
      want(3);
      return node("andor", [sub(0), sub(1), sub(2)]);
    case "and_n":
      want(2);
      return node("andor", [sub(0), sub(1), node("0")]);
    case "sha256":
    case "hash256":
    case "ripemd160":
    case "hash160":
      throw new MiniscriptError("hash locks are not supported");
    case "multi_a": {
      if (!tap) throw new MiniscriptError("multi_a is for Taproot: in P2WSH it is multi");
      if (a.length < 2) throw new MiniscriptError("multi_a takes a threshold and keys");
      const keys = a.slice(1).map(key);
      if (keys.length > 999) throw new MiniscriptError("multi_a takes at most 999 keys");
      return node("multi_a", [], { k: integer(a[0], 1, keys.length, "multi_a's threshold"), keys });
    }
    case "sortedmulti_a":
      throw new MiniscriptError("sortedmulti_a is not supported");
    default:
      throw new MiniscriptError(`unknown miniscript fragment: ${name}`);
  }
}

// ---------- types (BIP 379: base type, and the d and u properties) ----------

interface Type {
  base: "B" | "V" | "K" | "W";
  d: boolean;
  u: boolean;
}

function typeOf(ms: Miniscript, tap: boolean): Type {
  const s = ms.subs.map((m) => typeOf(m, tap));
  const need = (cond: boolean) => {
    if (!cond) throw new MiniscriptError(`${ms.f}: its arguments are not of the types it needs`);
  };
  switch (ms.f) {
    case "0":
      return { base: "B", d: true, u: true };
    case "1":
      return { base: "B", d: false, u: true };
    case "pk_k":
    case "pk_h":
      return { base: "K", d: true, u: true };
    case "older":
    case "after":
      return { base: "B", d: false, u: false };
    case "multi":
    case "multi_a":
      return { base: "B", d: true, u: true };
    case "thresh":
      need(s[0].base === "B" && s.slice(1).every((t) => t.base === "W") && s.every((t) => t.d && t.u));
      return { base: "B", d: true, u: true };
    case "and_v":
      need(s[0].base === "V" && ["B", "V", "K"].includes(s[1].base));
      return { base: s[1].base, d: false, u: s[1].u };
    case "and_b":
      need(s[0].base === "B" && s[1].base === "W");
      return { base: "B", d: s[0].d && s[1].d, u: true };
    case "andor":
      need(s[0].base === "B" && s[0].d && s[0].u && s[1].base === s[2].base && ["B", "V", "K"].includes(s[1].base));
      return { base: s[1].base, d: s[2].d, u: s[1].u && s[2].u };
    case "or_b":
      need(s[0].base === "B" && s[0].d && s[1].base === "W" && s[1].d);
      return { base: "B", d: true, u: true };
    case "or_c":
      need(s[0].base === "B" && s[0].d && s[0].u && s[1].base === "V");
      return { base: "V", d: false, u: false };
    case "or_d":
      need(s[0].base === "B" && s[0].d && s[0].u && s[1].base === "B");
      return { base: "B", d: s[1].d, u: s[1].u };
    case "or_i":
      need(s[0].base === s[1].base && ["B", "V", "K"].includes(s[0].base));
      return { base: s[0].base, d: s[0].d || s[1].d, u: s[0].u && s[1].u };
    case "a":
    case "s":
      need(s[0].base === "B");
      return { base: "W", d: s[0].d, u: s[0].u };
    case "c":
      need(s[0].base === "K");
      return { base: "B", d: s[0].d, u: true };
    case "d":
      need(s[0].base === "V");
      // d:X is u only in Tapscript, where MINIMALIF is consensus.
      return { base: "B", d: true, u: tap };
    case "v":
      need(s[0].base === "B");
      return { base: "V", d: false, u: false };
    case "j":
      need(s[0].base === "B");
      return { base: "B", d: true, u: s[0].u };
    case "n":
      need(s[0].base === "B");
      return { base: "B", d: s[0].d, u: true };
  }
}

/** The data a script pushes (keys, key hashes, numbers), in order; null if it does not parse. */
export function scriptPushes(script: Uint8Array): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  for (let pc = 0; pc < script.length; ) {
    const op = script[pc++];
    let n = -1;
    if (op >= 0x01 && op < OP.PUSHDATA1) n = op;
    else if (op === OP.PUSHDATA1) n = script[pc++];
    else if (op === OP.PUSHDATA2) {
      n = script[pc] | (script[pc + 1] << 8);
      pc += 2;
    }
    if (n < 0) continue;
    if (pc + n > script.length) return null;
    out.push(script.subarray(pc, (pc += n)));
  }
  return out;
}

/** True if the script has this public key, or its hash (as pk_h does). */
export function scriptHasKey(script: Uint8Array, pubkey: Uint8Array): boolean {
  const pushes = scriptPushes(script);
  if (!pushes) return false;
  const h = hash160(pubkey);
  return pushes.some((p) => sameBytes(p, pubkey) || sameBytes(p, h));
}

/** The miniscript as text, each key written by `key`. */
export function printMiniscript(ms: Miniscript, key: (index: number) => string): string {
  const p = (m: Miniscript) => printMiniscript(m, key);
  switch (ms.f) {
    case "0":
    case "1":
      return ms.f;
    case "pk_k":
    case "pk_h":
      return `${ms.f}(${key(ms.keys![0])})`;
    case "older":
    case "after":
      return `${ms.f}(${ms.n})`;
    case "multi":
    case "multi_a":
      return `${ms.f}(${ms.k},${ms.keys!.map(key).join(",")})`;
    case "thresh":
      return `thresh(${ms.k},${ms.subs.map(p).join(",")})`;
    case "a":
    case "s":
    case "c":
    case "d":
    case "v":
    case "j":
    case "n": {
      // Wrappers in a row are written together: v:c:pk_h(K) is vc:pk_h(K).
      const inner = p(ms.subs[0]);
      return /^[a-z]+:/.test(inner) ? `${ms.f}${inner}` : `${ms.f}:${inner}`;
    }
    default:
      return `${ms.f}(${ms.subs.map(p).join(",")})`;
  }
}

// ---------- script ----------

export const OP = {
  "0": 0x00, PUSHDATA1: 0x4c, PUSHDATA2: 0x4d, "1NEGATE": 0x4f, "1": 0x51, "16": 0x60,
  IF: 0x63, NOTIF: 0x64, ELSE: 0x67, ENDIF: 0x68, VERIFY: 0x69, TOALTSTACK: 0x6b, FROMALTSTACK: 0x6c,
  IFDUP: 0x73, DROP: 0x75, DUP: 0x76, SWAP: 0x7c, SIZE: 0x82, EQUAL: 0x87, EQUALVERIFY: 0x88,
  "0NOTEQUAL": 0x92, ADD: 0x93, BOOLAND: 0x9a, BOOLOR: 0x9b, NUMEQUAL: 0x9c, NUMEQUALVERIFY: 0x9d,
  HASH160: 0xa9, CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad, CHECKMULTISIG: 0xae, CHECKMULTISIGVERIFY: 0xaf,
  CHECKLOCKTIMEVERIFY: 0xb1, CHECKSEQUENCEVERIFY: 0xb2, CHECKSIGADD: 0xba,
} as const;

type Op = number | Uint8Array;

export const hash160 = (b: Uint8Array): Uint8Array => ripemd160(sha256(b));

/** A script number's minimal encoding (little-endian, sign bit on top). */
function scriptNum(n: number): Uint8Array {
  const out: number[] = [];
  let v = n;
  while (v > 0) {
    out.push(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (out.length && out[out.length - 1] & 0x80) out.push(0);
  return Uint8Array.from(out);
}

const num = (n: number): Op => (n === 0 ? OP["0"] : n <= 16 ? 0x50 + n : scriptNum(n));

function ops(ms: Miniscript, pubkeys: Uint8Array[]): Op[] {
  const sub = (i: number) => ops(ms.subs[i], pubkeys);
  switch (ms.f) {
    case "0":
      return [OP["0"]];
    case "1":
      return [OP["1"]];
    case "pk_k":
      return [pubkeys[ms.keys![0]]];
    case "pk_h":
      return [OP.DUP, OP.HASH160, hash160(pubkeys[ms.keys![0]]), OP.EQUALVERIFY];
    case "older":
      return [num(ms.n!), OP.CHECKSEQUENCEVERIFY];
    case "after":
      return [num(ms.n!), OP.CHECKLOCKTIMEVERIFY];
    case "multi":
      return [num(ms.k!), ...ms.keys!.map((k) => pubkeys[k]), num(ms.keys!.length), OP.CHECKMULTISIG];
    case "multi_a":
      return [...ms.keys!.flatMap((k, i) => [pubkeys[k], i ? OP.CHECKSIGADD : OP.CHECKSIG]), num(ms.k!), OP.NUMEQUAL];
    case "thresh":
      return [...sub(0), ...ms.subs.slice(1).flatMap((_, i) => [...sub(i + 1), OP.ADD]), num(ms.k!), OP.EQUAL];
    case "and_v":
      return [...sub(0), ...sub(1)];
    case "and_b":
      return [...sub(0), ...sub(1), OP.BOOLAND];
    case "andor":
      return [...sub(0), OP.NOTIF, ...sub(2), OP.ELSE, ...sub(1), OP.ENDIF];
    case "or_b":
      return [...sub(0), ...sub(1), OP.BOOLOR];
    case "or_c":
      return [...sub(0), OP.NOTIF, ...sub(1), OP.ENDIF];
    case "or_d":
      return [...sub(0), OP.IFDUP, OP.NOTIF, ...sub(1), OP.ENDIF];
    case "or_i":
      return [OP.IF, ...sub(0), OP.ELSE, ...sub(1), OP.ENDIF];
    case "a":
      return [OP.TOALTSTACK, ...sub(0), OP.FROMALTSTACK];
    case "s":
      return [OP.SWAP, ...sub(0)];
    case "c":
      return [...sub(0), OP.CHECKSIG];
    case "d":
      return [OP.DUP, OP.IF, ...sub(0), OP.ENDIF];
    case "v": {
      const x = sub(0);
      const last = x[x.length - 1];
      // CHECKSIG, CHECKMULTISIG, EQUAL and NUMEQUAL have a VERIFY form one opcode on.
      const verifiable: number[] = [OP.CHECKSIG, OP.CHECKMULTISIG, OP.EQUAL, OP.NUMEQUAL];
      if (typeof last === "number" && verifiable.includes(last)) return [...x.slice(0, -1), last + 1];
      return [...x, OP.VERIFY];
    }
    case "j":
      return [OP.SIZE, OP["0NOTEQUAL"], OP.IF, ...sub(0), OP.ENDIF];
    case "n":
      return [...sub(0), OP["0NOTEQUAL"]];
  }
}

function push(data: Uint8Array): number[] {
  if (data.length < OP.PUSHDATA1) return [data.length, ...data];
  if (data.length <= 0xff) return [OP.PUSHDATA1, data.length, ...data];
  return [OP.PUSHDATA2, data.length & 0xff, data.length >> 8, ...data];
}

/** The witness script (or Tapscript leaf) of the miniscript with these keys (one public key per key index, x-only in Tapscript). */
export function compile(ms: Miniscript, pubkeys: Uint8Array[]): Uint8Array {
  return Uint8Array.from(ops(ms, pubkeys).flatMap((op) => (typeof op === "number" ? [op] : push(op))));
}

// ---------- spending paths ----------

/** One way to spend: every group's k-of-keys signs, and every timelock has passed. */
export interface SpendPath {
  groups: { k: number; keys: number[] }[];
  /** Relative timelocks (older), as the script has them. */
  older: number[];
  /** Absolute timelocks (after). */
  after: number[];
}

const MAX_PATHS = 64;

function andPaths(a: SpendPath[], b: SpendPath[]): SpendPath[] {
  const out = a.flatMap((x) => b.map((y) => ({ groups: [...x.groups, ...y.groups], older: [...x.older, ...y.older], after: [...x.after, ...y.after] })));
  if (out.length > MAX_PATHS) throw new MiniscriptError("too many ways to spend to show");
  return out;
}

function combinations<T>(items: T[], k: number): T[][] {
  if (k === 0) return [[]];
  if (items.length < k) return [];
  const [first, ...rest] = items;
  return [...combinations(rest, k - 1).map((c) => [first, ...c]), ...combinations(rest, k)];
}

function rawPaths(ms: Miniscript): SpendPath[] {
  const sub = (i: number) => rawPaths(ms.subs[i]);
  const empty: SpendPath = { groups: [], older: [], after: [] };
  switch (ms.f) {
    case "0":
      return [];
    case "1":
      return [empty];
    case "pk_k":
    case "pk_h":
      return [{ ...empty, groups: [{ k: 1, keys: ms.keys! }] }];
    case "multi":
    case "multi_a":
      return [{ ...empty, groups: [{ k: ms.k!, keys: ms.keys! }] }];
    case "older":
      return [{ ...empty, older: [ms.n!] }];
    case "after":
      return [{ ...empty, after: [ms.n!] }];
    case "thresh": {
      const subs = ms.subs.map(rawPaths);
      // thresh(k, pk(A), s:pk(B), ...): one k-of-n group.
      const single = subs.map((p) => (p.length === 1 && p[0].groups.length === 1 && p[0].groups[0].k === 1 && p[0].groups[0].keys.length === 1 && !p[0].older.length && !p[0].after.length ? p[0].groups[0].keys[0] : null));
      if (single.every((k) => k !== null)) return [{ ...empty, groups: [{ k: ms.k!, keys: single as number[] }] }];
      const out: SpendPath[] = [];
      for (const chosen of combinations(subs, ms.k!)) {
        out.push(...chosen.reduce((acc, p) => andPaths(acc, p), [empty]));
        if (out.length > MAX_PATHS) throw new MiniscriptError("too many ways to spend to show");
      }
      return out;
    }
    case "and_v":
    case "and_b":
      return andPaths(sub(0), sub(1));
    case "andor":
      return [...andPaths(sub(0), sub(1)), ...sub(2)];
    case "or_b":
    case "or_c":
    case "or_d":
    case "or_i":
      return [...sub(0), ...sub(1)];
    default:
      return sub(0);
  }
}

/**
 * The ways the miniscript can be spent, each with its signers and timelocks: Liana's primary path (no timelock) and
 * its recovery paths. Groups that are each one key are shown as one all-of group.
 */
export function spendPaths(ms: Miniscript): SpendPath[] {
  return rawPaths(ms).map((p) => {
    if (p.groups.length > 1 && p.groups.every((g) => g.k === g.keys.length)) {
      const keys = p.groups.flatMap((g) => g.keys);
      return { ...p, groups: [{ k: keys.length, keys }] };
    }
    return p;
  });
}

/** Every relative timelock (older) in the miniscript. */
export function olderLocks(ms: Miniscript): number[] {
  return ms.f === "older" ? [ms.n!] : ms.subs.flatMap(olderLocks);
}

// ---------- satisfaction ----------

/** What a spend has: a key's signature, and which timelocks the transaction meets. */
export interface SatisfyContext {
  pubkey(key: number): Uint8Array;
  sig(key: number): Uint8Array | undefined;
  older(n: number): boolean;
  after(n: number): boolean;
}

/** A witness stack, bottom first, and its size in bytes. */
interface Wit {
  items: Uint8Array[];
  size: number;
}
type W = Wit | null;

const EMPTY = new Uint8Array();
const ONE = Uint8Array.of(1);
const wit = (...items: Uint8Array[]): Wit => ({ items, size: items.reduce((n, i) => n + i.length + 1, 0) });
/** Witnesses of scripts run one after another: the first one's items on top, so last. */
function seq(...ws: W[]): W {
  if (ws.some((w) => w === null)) return null;
  const parts = (ws as Wit[]).slice().reverse();
  return { items: parts.flatMap((w) => w.items), size: parts.reduce((n, w) => n + w.size, 0) };
}
const smaller = (a: W, b: W): W => (a === null ? b : b === null ? a : b.size < a.size ? b : a);

function satisfy(ms: Miniscript, ctx: SatisfyContext): { sat: W; dsat: W } {
  const s = ms.subs.map((m) => satisfy(m, ctx));
  switch (ms.f) {
    case "0":
      return { sat: null, dsat: wit() };
    case "1":
      return { sat: wit(), dsat: null };
    case "pk_k": {
      const sig = ctx.sig(ms.keys![0]);
      return { sat: sig ? wit(sig) : null, dsat: wit(EMPTY) };
    }
    case "pk_h": {
      const pk = ctx.pubkey(ms.keys![0]);
      const sig = ctx.sig(ms.keys![0]);
      return { sat: sig ? wit(sig, pk) : null, dsat: wit(EMPTY, pk) };
    }
    case "older":
      return { sat: ctx.older(ms.n!) ? wit() : null, dsat: null };
    case "after":
      return { sat: ctx.after(ms.n!) ? wit() : null, dsat: null };
    case "multi": {
      // OP_CHECKMULTISIG takes the signatures in key order, under its extra (empty) element.
      const sigs = ms.keys!.map((k) => ctx.sig(k)).filter((x): x is Uint8Array => !!x).slice(0, ms.k);
      return {
        sat: sigs.length === ms.k ? wit(EMPTY, ...sigs) : null,
        dsat: wit(...Array<Uint8Array>(ms.k! + 1).fill(EMPTY)),
      };
    }
    case "multi_a": {
      // The first key's CHECKSIG takes the top item: so the last key's signature is at the bottom. Exactly k signatures
      // (the first k there are, in key order), an empty item for every other key.
      let left = ms.k!;
      const items = ms.keys!.map((k) => {
        const sig = left ? ctx.sig(k) : undefined;
        if (sig) left--;
        return sig ?? EMPTY;
      });
      return { sat: left ? null : wit(...items.reverse()), dsat: wit(...Array<Uint8Array>(ms.keys!.length).fill(EMPTY)) };
    }
    case "thresh": {
      // The k subs whose satisfaction costs least over their dissatisfaction, the others dissatisfied.
      const order = s.map((x, i) => i).filter((i) => s[i].dsat !== null);
      if (order.length !== s.length) return { sat: null, dsat: null };
      const cost = (i: number) => (s[i].sat ? s[i].sat!.size - s[i].dsat!.size : Infinity);
      order.sort((a, b) => cost(a) - cost(b));
      const chosen = new Set(order.slice(0, ms.k));
      const sat = [...chosen].every((i) => s[i].sat) ? seq(...s.map((x, i) => (chosen.has(i) ? x.sat : x.dsat))) : null;
      return { sat, dsat: seq(...s.map((x) => x.dsat)) };
    }
    case "and_v":
      return { sat: seq(s[0].sat, s[1].sat), dsat: seq(s[0].sat, s[1].dsat) };
    case "and_b":
      return { sat: seq(s[0].sat, s[1].sat), dsat: seq(s[0].dsat, s[1].dsat) };
    case "andor":
      return { sat: smaller(seq(s[0].sat, s[1].sat), seq(s[0].dsat, s[2].sat)), dsat: seq(s[0].dsat, s[2].dsat) };
    case "or_b":
      return { sat: smaller(seq(s[0].sat, s[1].dsat), seq(s[0].dsat, s[1].sat)), dsat: seq(s[0].dsat, s[1].dsat) };
    case "or_c":
      return { sat: smaller(s[0].sat, seq(s[0].dsat, s[1].sat)), dsat: null };
    case "or_d":
      return { sat: smaller(s[0].sat, seq(s[0].dsat, s[1].sat)), dsat: seq(s[0].dsat, s[1].dsat) };
    case "or_i": {
      // OP_IF's argument comes last, on top: 1 for the first branch, empty for the second.
      const pick = (x: W, branch: Uint8Array) => (x ? { items: [...x.items, branch], size: x.size + branch.length + 1 } : null);
      return { sat: smaller(pick(s[0].sat, ONE), pick(s[1].sat, EMPTY)), dsat: smaller(pick(s[0].dsat, ONE), pick(s[1].dsat, EMPTY)) };
    }
    case "a":
    case "s":
    case "c":
    case "n":
      return s[0];
    case "d":
      return { sat: s[0].sat && { items: [...s[0].sat.items, ONE], size: s[0].sat.size + 2 }, dsat: wit(EMPTY) };
    case "v":
      return { sat: s[0].sat, dsat: null };
    case "j":
      return { sat: s[0].sat, dsat: wit(EMPTY) };
  }
}

/** The smallest witness (bottom first, without the witness script) that spends the miniscript, or null. */
export function satisfaction(ms: Miniscript, ctx: SatisfyContext): Uint8Array[] | null {
  return satisfy(ms, ctx).sat?.items ?? null;
}

/** The fewest more signatures the spend needs, given the signatures it has and the timelocks it meets (Infinity: none will do). */
export function missingSignatures(ms: Miniscript, signed: (key: number) => boolean, ctx: Pick<SatisfyContext, "older" | "after">): number {
  const sub = (i: number) => missingSignatures(ms.subs[i], signed, ctx);
  switch (ms.f) {
    case "0":
      return Infinity;
    case "1":
      return 0;
    case "pk_k":
    case "pk_h":
      return signed(ms.keys![0]) ? 0 : 1;
    case "older":
      return ctx.older(ms.n!) ? 0 : Infinity;
    case "after":
      return ctx.after(ms.n!) ? 0 : Infinity;
    case "multi":
    case "multi_a":
      return Math.max(0, ms.k! - ms.keys!.filter(signed).length);
    case "thresh":
      return ms.subs.map((_, i) => sub(i)).sort((a, b) => a - b).slice(0, ms.k).reduce((a, b) => a + b, 0);
    case "and_v":
    case "and_b":
      return sub(0) + sub(1);
    case "andor":
      return Math.min(sub(0) + sub(1), sub(2));
    case "or_b":
    case "or_c":
    case "or_d":
    case "or_i":
      return Math.min(sub(0), sub(1));
    default:
      return sub(0);
  }
}

// ---------- timelocks (BIP 68, 112, 65) ----------

const SEQUENCE_DISABLE = 0x80000000;
const SEQUENCE_TYPE = 0x00400000;
const SEQUENCE_MASK = 0x0000ffff;

/** True if an input with this nSequence, in a transaction of this version, meets older(n). */
export function olderMet(n: number, sequence: number, version: number): boolean {
  if (n & SEQUENCE_DISABLE) return true;
  if (version < 2 || sequence & SEQUENCE_DISABLE) return false;
  if ((n & SEQUENCE_TYPE) !== (sequence & SEQUENCE_TYPE)) return false;
  return (n & SEQUENCE_MASK) <= (sequence & SEQUENCE_MASK);
}

/** True if a transaction with this nLockTime, and this input's nSequence, meets after(n). */
export function afterMet(n: number, lockTime: number, sequence: number): boolean {
  if (sequence === 0xffffffff) return false;
  if ((n < 500_000_000) !== (lockTime < 500_000_000)) return false;
  return n <= lockTime;
}

// ---------- the interpreter ----------

export interface RunContext {
  checkSig(pubkey: Uint8Array, sig: Uint8Array): boolean;
  /** Tapscript (BIP 342): OP_CHECKSIGADD, and no OP_CHECKMULTISIG. */
  tap?: boolean;
  older(n: number): boolean;
  after(n: number): boolean;
}

function readNum(b: Uint8Array): number {
  if (b.length > 5) throw new Error("number too long");
  if (!b.length) return 0;
  let n = 0;
  for (let i = b.length - 1; i >= 0; i--) n = n * 256 + (i === b.length - 1 ? b[i] & 0x7f : b[i]);
  return b[b.length - 1] & 0x80 ? -n : n;
}

const truthy = (b: Uint8Array) => b.some((x, i) => x !== 0 && !(i === b.length - 1 && x === 0x80));
const bool = (v: boolean) => (v ? ONE : EMPTY);
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Runs a P2WSH witness (its stack, without the witness script) against the witness script, under segwit v0's rules
 * (MINIMALIF, NULLFAIL, NULLDUMMY and a clean stack, as Core's standardness has them), or a Tapscript leaf's stack
 * against the leaf (ctx.tap: the same rules, which Tapscript makes consensus, with OP_CHECKSIGADD). Only the opcodes miniscript
 * uses are known: any other fails. The signatures that checked, with their keys, or null if the witness does not spend.
 */
export function runWitness(stackIn: Uint8Array[], script: Uint8Array, ctx: RunContext): { pubkey: Uint8Array; sig: Uint8Array }[] | null {
  const stack = stackIn.slice();
  const alt: Uint8Array[] = [];
  const exec: boolean[] = [];
  const signers: { pubkey: Uint8Array; sig: Uint8Array }[] = [];
  const pop = () => {
    const v = stack.pop();
    if (v === undefined) throw new Error("stack empty");
    return v;
  };
  try {
    for (let pc = 0; pc < script.length; ) {
      const op = script[pc++];
      const running = exec.every(Boolean);
      let data: Uint8Array | null = null;
      if (op >= 0x01 && op < OP.PUSHDATA1) data = script.subarray(pc, (pc += op));
      else if (op === OP.PUSHDATA1) {
        const n = script[pc++];
        data = script.subarray(pc, (pc += n));
      } else if (op === OP.PUSHDATA2) {
        const n = script[pc] | (script[pc + 1] << 8);
        pc += 2;
        data = script.subarray(pc, (pc += n));
      }
      if (pc > script.length) return null;
      if (data) {
        if (running) stack.push(data);
        continue;
      }
      if (op === OP.IF || op === OP.NOTIF) {
        let v = false;
        if (running) {
          const top = pop();
          if (top.length > 1 || (top.length === 1 && top[0] !== 1)) return null; // MINIMALIF
          v = top.length === 1;
          if (op === OP.NOTIF) v = !v;
        }
        exec.push(v);
        continue;
      }
      if (op === OP.ELSE) {
        if (!exec.length) return null;
        exec.push(!exec.pop()!);
        continue;
      }
      if (op === OP.ENDIF) {
        if (!exec.length) return null;
        exec.pop();
        continue;
      }
      if (!running) continue;
      if (op === OP["0"]) stack.push(EMPTY);
      else if (op >= OP["1"] && op <= OP["16"]) stack.push(Uint8Array.of(op - 0x50));
      else if (op === OP.VERIFY) {
        if (!truthy(pop())) return null;
      } else if (op === OP.TOALTSTACK) alt.push(pop());
      else if (op === OP.FROMALTSTACK) {
        const v = alt.pop();
        if (!v) return null;
        stack.push(v);
      } else if (op === OP.IFDUP) {
        const v = pop();
        stack.push(v);
        if (truthy(v)) stack.push(v);
      } else if (op === OP.DROP) pop();
      else if (op === OP.DUP) {
        const v = pop();
        stack.push(v, v);
      } else if (op === OP.SWAP) {
        const a = pop();
        const b = pop();
        stack.push(a, b);
      } else if (op === OP.SIZE) {
        const v = pop();
        stack.push(v, scriptNum(v.length));
      } else if (op === OP.EQUAL || op === OP.EQUALVERIFY) {
        const eq = sameBytes(pop(), pop());
        if (op === OP.EQUALVERIFY) {
          if (!eq) return null;
        } else stack.push(bool(eq));
      } else if (op === OP["0NOTEQUAL"]) stack.push(bool(readNum(pop()) !== 0));
      else if (op === OP.ADD) stack.push(scriptNum(readNum(pop()) + readNum(pop())));
      else if (op === OP.BOOLAND || op === OP.BOOLOR) {
        const a = readNum(pop()) !== 0;
        const b = readNum(pop()) !== 0;
        stack.push(bool(op === OP.BOOLAND ? a && b : a || b));
      } else if (op === OP.NUMEQUAL || op === OP.NUMEQUALVERIFY) {
        const eq = readNum(pop()) === readNum(pop());
        if (op === OP.NUMEQUALVERIFY) {
          if (!eq) return null;
        } else stack.push(bool(eq));
      } else if (op === OP.HASH160) stack.push(hash160(pop()));
      else if (op === OP.CHECKSIG || op === OP.CHECKSIGVERIFY) {
        const pk = pop();
        const sig = pop();
        const ok = sig.length > 0 && ctx.checkSig(pk, sig);
        if (!ok && sig.length) return null; // NULLFAIL
        if (ok) signers.push({ pubkey: pk, sig });
        if (op === OP.CHECKSIGVERIFY) {
          if (!ok) return null;
        } else stack.push(bool(ok));
      } else if (op === OP.CHECKSIGADD && ctx.tap) {
        const pk = pop();
        const n = readNum(pop());
        if (n < 0) return null; // never in a miniscript's script
        const sig = pop();
        const ok = sig.length > 0 && ctx.checkSig(pk, sig);
        if (!ok && sig.length) return null;
        if (ok) signers.push({ pubkey: pk, sig });
        stack.push(scriptNum(n + (ok ? 1 : 0)));
      } else if ((op === OP.CHECKMULTISIG || op === OP.CHECKMULTISIGVERIFY) && !ctx.tap) {
        const n = readNum(pop());
        if (n < 0 || n > 20) return null;
        const pks = Array.from({ length: n }, pop).reverse();
        const m = readNum(pop());
        if (m < 0 || m > n) return null;
        const sigs = Array.from({ length: m }, pop).reverse();
        if (pop().length) return null; // NULLDUMMY
        let k = 0;
        let ok = true;
        for (const sig of sigs) {
          while (k < pks.length && !(sig.length && ctx.checkSig(pks[k], sig))) k++;
          if (k === pks.length) {
            ok = false;
            break;
          }
          signers.push({ pubkey: pks[k++], sig });
        }
        if (!ok && sigs.some((s) => s.length)) return null; // NULLFAIL
        if (op === OP.CHECKMULTISIGVERIFY) {
          if (!ok) return null;
        } else stack.push(bool(ok));
      } else if (op === OP.CHECKSEQUENCEVERIFY || op === OP.CHECKLOCKTIMEVERIFY) {
        const top = stack[stack.length - 1];
        if (!top) return null;
        const n = readNum(top);
        if (n < 0) return null;
        if (!(op === OP.CHECKSEQUENCEVERIFY ? ctx.older(n) : ctx.after(n))) return null;
      } else return null;
    }
  } catch {
    return null;
  }
  if (exec.length || stack.length !== 1 || !truthy(stack[0])) return null;
  return signers;
}
