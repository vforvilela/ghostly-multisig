/**
 * Multisig's messages, carried as the JSON value of `ghostly.chat.send` (one `apps/1` data frame each). docs/protocol.md
 * describes them for anyone writing another client.
 *
 * Every message is `{"p": "multisig", "v": 1, "k": <kind>, ...}`:
 *   hello {w, re?}         the sender's wallet id (see descriptor.ts), or null before a wallet is set; re = 1 in answer
 *   psbt  {id, n, of, d}   part n (0-based) of `of` of a PSBT in base64; id = its unsigned txid
 *   ack   {id, m}          "I hold transaction id"; m = the signatures it still misses
 *
 * Everything from the peer is untrusted: parseMessage checks the size first, then every field's type, shape and range,
 * and refuses the message whole. Unknown extra fields are ignored. A frame of a newer version gives "newer-version".
 * A reassembled PSBT whose txid is not its `id` is refused (Reassembler).
 */
import type { MiniAppJson } from "./vendor/miniApp.ts";

export const PROTOCOL = "multisig";
export const VERSION = 1;
/** One message, serialized as UTF-8 JSON. Half the 32 KiB `paired-app` data cap, so there is room to spare. */
export const MAX_MESSAGE_BYTES = 16 * 1024;
/** Base64 characters in one psbt part. A 2-of-3 PSBT of two inputs is about 2.5 KB: one part. */
export const CHUNK_CHARS = 12_000;
/** Parts of one PSBT: about 190 KB, past any multisig spend this app is for. */
export const MAX_PARTS = 16;
/** Signatures a multisig can miss: 15 keys. */
const MAX_MISSING = 15;

export type Message =
  | { k: "hello"; w: string | null; re?: 1 }
  | { k: "psbt"; id: string; n: number; of: number; d: string }
  | { k: "ack"; id: string; m: number };

export type ParseFailure = "too-big" | "malformed" | "newer-version";
export type Parsed = { ok: true; message: Message } | { ok: false; reason: ParseFailure };

const TXID = /^[0-9a-f]{64}$/;
const WALLET_ID = /^[0-9a-f]{16}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

const jsonBytes = (value: unknown): number => {
  try {
    return new TextEncoder().encode(JSON.stringify(value)).length;
  } catch {
    return Infinity;
  }
};
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isInt = (v: unknown, min: number, max: number): v is number => Number.isInteger(v) && (v as number) >= min && (v as number) <= max;
const isTxid = (v: unknown): v is string => typeof v === "string" && TXID.test(v);

export function parseMessage(value: unknown): Parsed {
  if (jsonBytes(value) > MAX_MESSAGE_BYTES) return { ok: false, reason: "too-big" };
  const bad: Parsed = { ok: false, reason: "malformed" };
  if (!isObject(value) || value.p !== PROTOCOL || !Number.isInteger(value.v) || (value.v as number) < 1) return bad;
  if ((value.v as number) > VERSION) return { ok: false, reason: "newer-version" };
  switch (value.k) {
    case "hello": {
      if (value.w !== null && !(typeof value.w === "string" && WALLET_ID.test(value.w))) return bad;
      if (value.re !== undefined && value.re !== 1) return bad;
      return { ok: true, message: value.re ? { k: "hello", w: value.w, re: 1 } : { k: "hello", w: value.w } };
    }
    case "psbt": {
      if (!isTxid(value.id) || !isInt(value.of, 1, MAX_PARTS) || !isInt(value.n, 0, (value.of as number) - 1)) return bad;
      if (typeof value.d !== "string" || value.d.length === 0 || value.d.length > CHUNK_CHARS || !/^[A-Za-z0-9+/=]+$/.test(value.d)) return bad;
      return { ok: true, message: { k: "psbt", id: value.id, n: value.n, of: value.of, d: value.d } };
    }
    case "ack":
      if (!isTxid(value.id) || !isInt(value.m, 0, MAX_MISSING)) return bad;
      return { ok: true, message: { k: "ack", id: value.id, m: value.m } };
    default:
      return bad;
  }
}

/** The frame for a message. */
export const frame = (message: Message): MiniAppJson => ({ p: PROTOCOL, v: VERSION, ...message }) as MiniAppJson;

/** A PSBT as psbt messages, CHUNK_CHARS each. */
export function chunk(id: string, base64: string): Message[] {
  const of = Math.ceil(base64.length / CHUNK_CHARS);
  if (of < 1 || of > MAX_PARTS) throw new Error("PSBT too large to send");
  return Array.from({ length: of }, (_, n) => ({ k: "psbt", id, n, of, d: base64.slice(n * CHUNK_CHARS, (n + 1) * CHUNK_CHARS) }));
}

/**
 * Collects psbt parts until one PSBT is whole. Holds parts of one transaction at a time: parts of another one start
 * over, so a peer cannot fill memory with half-sent PSBTs.
 */
export class Reassembler {
  private id: string | null = null;
  private parts: (string | undefined)[] = [];

  /** The whole base64 PSBT once its last part is in, else null. */
  add(message: Extract<Message, { k: "psbt" }>): string | null {
    if (message.id !== this.id || message.of !== this.parts.length) {
      this.id = message.id;
      this.parts = new Array<string | undefined>(message.of).fill(undefined);
    }
    this.parts[message.n] = message.d;
    if (this.parts.some((p) => p === undefined)) return null;
    const whole = this.parts.join("");
    this.id = null;
    this.parts = [];
    return BASE64.test(whole) ? whole : null;
  }
}
