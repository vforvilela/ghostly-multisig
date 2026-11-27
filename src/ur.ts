/**
 * Uniform Resources (BCR-2020-005), the text inside the animated QR codes that air-gapped signers (Passport, Keystone,
 * Jade, Sparrow) read: `ur:crypto-psbt/...` for a PSBT, `ur:bytes/...` for a wallet file.
 *
 * Our own small encoder (no dependency): bytewords "minimal" (two letters a byte, CRC-32 at the end), the message as
 * a CBOR byte string, and fountain codes for messages that do not fit one QR: parts 1..n carry the fragments in
 * order, later parts XOR a random mix of them, so a scanner that missed a frame still finishes. The mixing follows
 * the reference exactly (Xoshiro256** seeded by SHA-256, Vose alias sampling): scripts/interop/ur.mjs checks every
 * part against @ngraveio/bc-ur, the library Keystone's and Passport's apps use.
 *
 * The decoder reads what a person pastes: a single part, or every part of a multi-part message (pure fragments; mixed
 * parts are solved by peeling).
 */
import { sha256 } from "@noble/hashes/sha2.js";

const WORDS =
  "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";
/** The two letters (first and last of each word) for every byte, and back. */
const MINIMAL = Array.from({ length: 256 }, (_, b) => WORDS[b * 4] + WORDS[b * 4 + 3]);
const FROM_MINIMAL = new Map(MINIMAL.map((m, b) => [m, b]));

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of data) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const be32 = (n: number) => new Uint8Array([n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) out.set(p, (at += p.length) - p.length);
  return out;
}

export function bytewords(data: Uint8Array): string {
  return Array.from(concat(data, be32(crc32(data))), (b) => MINIMAL[b]).join("");
}

export function fromBytewords(text: string): Uint8Array {
  const t = text.toLowerCase();
  if (t.length % 2 || t.length < 10) throw new UrError("not bytewords");
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = FROM_MINIMAL.get(t.slice(2 * i, 2 * i + 2));
    if (b === undefined) throw new UrError("not bytewords");
    out[i] = b;
  }
  const body = out.subarray(0, -4);
  if (crc32(body) !== new DataView(out.buffer, out.length - 4).getUint32(0)) throw new UrError("a damaged QR part (checksum)");
  return body;
}

export class UrError extends Error {}

// ---------- CBOR: just what UR needs (unsigned ints, byte strings, a 5-item array) ----------

function cborHead(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) return new Uint8Array([m | n]);
  if (n < 0x100) return new Uint8Array([m | 24, n]);
  if (n < 0x10000) return new Uint8Array([m | 25, n >> 8, n & 0xff]);
  return concat(new Uint8Array([m | 26]), be32(n));
}
const cborBytes = (data: Uint8Array) => concat(cborHead(2, data.length), data);

function cborRead(data: Uint8Array, at: number): { major: number; n: number; at: number } {
  if (at >= data.length) throw new UrError("short CBOR");
  const major = data[at] >> 5;
  const low = data[at] & 31;
  if (low < 24) return { major, n: low, at: at + 1 };
  const size = { 24: 1, 25: 2, 26: 4 }[low];
  if (!size || at + 1 + size > data.length) throw new UrError("unsupported CBOR");
  let n = 0;
  for (let i = 1; i <= size; i++) n = n * 256 + data[at + i];
  return { major, n, at: at + 1 + size };
}

function readCborBytes(data: Uint8Array, at = 0): { bytes: Uint8Array; at: number } {
  const h = cborRead(data, at);
  if (h.major !== 2 || h.at + h.n > data.length) throw new UrError("not a CBOR byte string");
  return { bytes: data.slice(h.at, h.at + h.n), at: h.at + h.n };
}

// ---------- fountain codes ----------

const MASK = (1n << 64n) - 1n;
const rotl = (x: bigint, k: bigint) => ((x << k) | (x >> (64n - k))) & MASK;

/** Xoshiro256**, seeded from SHA-256 of the seed (big-endian words), as in the reference. */
function xoshiro(seed: Uint8Array): () => number {
  const d = sha256(seed);
  const s = [0, 1, 2, 3].map((i) => d.subarray(i * 8, i * 8 + 8).reduce((v, b) => (v << 8n) | BigInt(b), 0n));
  return () => {
    const result = (rotl((s[1] * 5n) & MASK, 7n) * 9n) & MASK;
    const t = (s[1] << 17n) & MASK;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45n);
    return Number(result) / 2 ** 64;
  };
}

/** Vose's alias method over p(k) = 1/k, k = 1..n, built in the reference's order. */
function chooseDegree(n: number, next: () => number): number {
  const p = Array.from({ length: n }, (_, i) => 1 / (i + 1));
  const sum = p.reduce((a, b) => a + b, 0);
  const scaled = p.map((x) => (x * n) / sum);
  const prob: number[] = new Array(n);
  const alias: number[] = new Array(n);
  const small: number[] = [];
  const large: number[] = [];
  for (let i = n - 1; i >= 0; i--) (scaled[i] < 1 ? small : large).push(i);
  while (small.length && large.length) {
    const less = small.pop()!;
    const more = large.pop()!;
    prob[less] = scaled[less];
    alias[less] = more;
    scaled[more] = scaled[more] + scaled[less] - 1;
    (scaled[more] < 1 ? small : large).push(more);
  }
  while (large.length) prob[large.pop()!] = 1;
  while (small.length) prob[small.pop()!] = 1;
  const c = Math.floor(next() * n);
  return (next() < prob[c] ? c : alias[c]) + 1;
}

/** Which fragments part `seq` (1-based) XORs together. */
export function chooseFragments(seq: number, count: number, checksum: number): number[] {
  if (seq <= count) return [seq - 1];
  const next = xoshiro(concat(be32(seq), be32(checksum)));
  const degree = chooseDegree(count, next);
  const remaining = Array.from({ length: count }, (_, i) => i);
  const picked: number[] = [];
  while (remaining.length) picked.push(remaining.splice(Math.floor(next() * remaining.length), 1)[0]);
  return picked.slice(0, degree);
}

function fragmentLength(messageLength: number, max: number, min = 10): number {
  const most = Math.ceil(messageLength / min);
  let len = 0;
  for (let count = 1; count <= most; count++) {
    len = Math.ceil(messageLength / count);
    if (len <= max) break;
  }
  return len;
}

export type UrType = "crypto-psbt" | "bytes";

/**
 * A UR for `data`, as parts of at most `maxFragment` bytes each. `part(seq)` gives part `seq` (1, 2, 3, ... for ever:
 * after the n pure parts come the mixed ones). A message that fits one fragment is a single part with no sequence.
 */
export function urEncoder(type: UrType, data: Uint8Array, maxFragment = 200): { count: number; part: (seq: number) => string } {
  const message = cborBytes(data);
  const len = fragmentLength(message.length, maxFragment);
  const count = Math.ceil(message.length / len);
  if (count === 1) {
    const single = `ur:${type}/${bytewords(message)}`;
    return { count, part: () => single };
  }
  const checksum = crc32(message);
  const padded = new Uint8Array(len * count);
  padded.set(message);
  const fragments = Array.from({ length: count }, (_, i) => padded.subarray(i * len, (i + 1) * len));
  return {
    count,
    part: (seq) => {
      const mixed = new Uint8Array(len);
      for (const i of chooseFragments(seq, count, checksum)) for (let j = 0; j < len; j++) mixed[j] ^= fragments[i][j];
      const body = concat(new Uint8Array([0x85]), cborHead(0, seq), cborHead(0, count), cborHead(0, message.length), cborHead(0, checksum), cborBytes(mixed));
      return `ur:${type}/${seq}-${count}/${bytewords(body)}`;
    },
  };
}

/**
 * The payload of pasted UR text: one part, or all the parts of one message (one per line or space-separated, any
 * order, mixed parts allowed). Throws UrError with a plain reason.
 */
export function urDecode(text: string): { type: string; data: Uint8Array } {
  const parts = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!parts.length || !parts.every((p) => p.startsWith("ur:"))) throw new UrError("not a UR");
  const parsed = parts.map((p) => {
    const m = /^ur:([a-z0-9-]+)\/(?:(\d+)-(\d+)\/)?([a-z]+)$/.exec(p);
    if (!m) throw new UrError("not a UR");
    return { type: m[1], seq: m[2] ? Number(m[2]) : 0, count: m[3] ? Number(m[3]) : 0, body: fromBytewords(m[4]) };
  });
  const type = parsed[0].type;
  if (parsed.some((p) => p.type !== type)) throw new UrError("parts of different URs");
  if (!parsed[0].seq) {
    if (parsed.length !== 1) throw new UrError("parts of different URs");
    return { type, data: readCborBytes(parsed[0].body).bytes };
  }
  // Multi-part: [seq, count, messageLength, checksum, fragment].
  let shape: { count: number; length: number; checksum: number; size: number } | null = null;
  const pending: { idx: Set<number>; data: Uint8Array }[] = [];
  for (const p of parsed) {
    if (p.body[0] !== 0x85) throw new UrError("not a UR part");
    let at = 1;
    const ints: number[] = [];
    for (let i = 0; i < 4; i++) {
      const h = cborRead(p.body, at);
      if (h.major !== 0) throw new UrError("not a UR part");
      ints.push(h.n);
      at = h.at;
    }
    const [seq, count, length, checksum] = ints;
    const fragment = readCborBytes(p.body, at).bytes;
    shape ??= { count, length, checksum, size: fragment.length };
    if (count !== shape.count || length !== shape.length || checksum !== shape.checksum || fragment.length !== shape.size || seq !== p.seq) {
      throw new UrError("parts of different URs");
    }
    pending.push({ idx: new Set(chooseFragments(seq, count, checksum)), data: fragment });
  }
  const s = shape!;
  const solved: (Uint8Array | undefined)[] = Array.from({ length: s.count }, () => undefined);
  // Peel: a part with one unknown fragment left gives that fragment.
  for (let progress = true; progress; ) {
    progress = false;
    for (const p of pending) {
      for (const i of [...p.idx]) {
        if (!solved[i]) continue;
        p.idx.delete(i);
        p.data = p.data.map((b, j) => b ^ solved[i]![j]);
      }
      if (p.idx.size === 1) {
        const [i] = p.idx;
        solved[i] = p.data;
        p.idx.clear();
        progress = true;
      }
    }
  }
  const missing = solved.filter((f) => !f).length;
  if (missing) throw new UrError(`${missing} of ${s.count} QR parts missing`);
  const message = concat(...(solved as Uint8Array[])).subarray(0, s.length);
  if (crc32(message) !== s.checksum) throw new UrError("a damaged QR part (checksum)");
  return { type, data: readCborBytes(message).bytes };
}
