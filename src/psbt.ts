/**
 * What a PSBT does, read against the person's own wallet: where every satoshi goes, which output is really their change,
 * the fee, and how many of the co-signers have signed. Nothing here signs: signing stays in the person's coordinator and
 * hardware wallet, and their screen is the one to trust (see docs/design.md).
 */
import { Address, NETWORK, OutScript, TEST_NETWORK, TaprootControlBlock, Transaction, p2sh, p2wsh, utils as btcUtils } from "@scure/btc-signer";
import { base64, hex } from "@scure/base";
import { urDecode } from "./ur.ts";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { deriveScript, derivePubkeys, deriveTaproot, fingerprints, tapBranch, tapLeafHash, TAPSCRIPT_LEAF, type TaprootAddress, type Wallet } from "./descriptor.ts";
import { afterMet, compile, missingSignatures, olderLocks, olderMet, runWitness, satisfaction, scriptHasKey } from "./miniscript.ts";

export type Network = "main" | "test" | "regtest";

const NETWORKS = {
  main: NETWORK,
  test: TEST_NETWORK,
  regtest: { ...TEST_NETWORK, bech32: "bcrt" },
} as const;

/** Most PSBTs of a few inputs are 2-5 KB; a pasted text past this is not one. */
export const MAX_PSBT_TEXT = 200_000;

export class PsbtError extends Error {}

const OPTS = { allowUnknownOutputs: true, allowUnknown: true } as const;

/** The PSBT in base64 (as coordinators copy it) or hex. */
export function decodePsbt(text: string): Uint8Array {
  // The text of an air-gapped signer's QR codes: ur:crypto-psbt, one part or all of them.
  if (/^\s*ur:/i.test(text)) {
    if (text.length > 4 * MAX_PSBT_TEXT) throw new PsbtError("too long to be a PSBT");
    let ur: { type: string; data: Uint8Array };
    try {
      ur = urDecode(text);
    } catch (e) {
      throw new PsbtError(`QR text that could not be read: ${(e as Error).message}`);
    }
    if (ur.type !== "crypto-psbt") throw new PsbtError(`QR text of a ${ur.type}, not a PSBT (crypto-psbt)`);
    return ur.data;
  }
  const clean = text.replace(/\s+/g, "");
  if (!clean) throw new PsbtError("paste a PSBT");
  if (clean.length > MAX_PSBT_TEXT) throw new PsbtError("too long to be a PSBT");
  if (isRawTransaction(clean)) throw new PsbtError(FINISHED);
  try {
    if (/^70736274ff[0-9a-f]*$/i.test(clean)) return hex.decode(clean.toLowerCase());
    return base64.decode(clean);
  } catch {
    throw new PsbtError("not a PSBT: copy it again from your wallet, in base64");
  }
}

const FINISHED = "a finished, signed transaction, not a PSBT: it can be broadcast as it is, or export the PSBT to merge it";

/**
 * A raw transaction in hex, which is also valid base64. Electrum hands one out once its signature completes the spend,
 * and so does any wallet asked to "finalise". Only a whole, signed transaction counts: one without witnesses or
 * scriptSigs is still a draft that someone pasted by mistake, and reads as "not a PSBT" like any other junk.
 */
function isRawTransaction(text: string): boolean {
  if (!/^0[12]000000[0-9a-f]+$/i.test(text) || text.length % 2) return false;
  try {
    const tx = Transaction.fromRaw(hex.decode(text.toLowerCase()), { ...OPTS, disableScriptCheck: true });
    return tx.inputsLength > 0 && Array.from({ length: tx.inputsLength }, (_, i) => tx.getInput(i)).every((i) => i.finalScriptWitness?.length || i.finalScriptSig?.length);
  } catch {
    return false;
  }
}

export function readPsbt(text: string | Uint8Array): Transaction {
  const bytes = typeof text === "string" ? decodePsbt(text) : text;
  // BIP 370 lets a v2 PSBT gain inputs and outputs after signing starts, and every message here is v0: refuse it
  // whole, before parsing, rather than convert it under the person's feet.
  const version = psbtVersion(bytes);
  if (version !== null && version !== 0) throw new PsbtError(`PSBT version ${version}: export it from your wallet as version 0`);
  try {
    return Transaction.fromPSBT(bytes, OPTS);
  } catch (e) {
    throw new PsbtError(`not a PSBT this app can read (${(e as Error).message})`);
  }
}

/** PSBT_GLOBAL_VERSION (key 0xfb) from the global map: 0 when absent, null when the bytes are not a PSBT's framing. */
function psbtVersion(bytes: Uint8Array): number | null {
  let at = 5; // "psbt" 0xff
  const size = (): number | null => {
    if (at >= bytes.length) return null;
    const first = bytes[at++];
    if (first < 0xfd) return first;
    const len = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    if (len === 8 || at + len > bytes.length) return null; // no global key or value is 4 GB
    let n = 0;
    for (let i = len - 1; i >= 0; i--) n = n * 256 + bytes[at + i];
    at += len;
    return n;
  };
  for (;;) {
    const keyLen = size();
    if (keyLen === null) return null;
    if (keyLen === 0) return 0;
    const key = bytes.subarray(at, at + keyLen);
    at += keyLen;
    const valueLen = size();
    if (valueLen === null || at + valueLen > bytes.length) return null;
    if (keyLen === 1 && key[0] === 0xfb) {
      if (valueLen !== 4) return null;
      return new DataView(bytes.buffer, bytes.byteOffset + at, 4).getUint32(0, true);
    }
    at += valueLen;
  }
}

export const toBase64 = (tx: Transaction): string => base64.encode(tx.toPSBT());

/**
 * A file's bytes, as a signer saves a PSBT to microSD: binary (Passport, Keystone, Coldcard, Sparrow's .psbt) or text
 * (base64, hex or UR). The caller reads at most MAX_PSBT_TEXT + 1 bytes, so a huge file reads as "too long".
 */
export function psbtFile(bytes: Uint8Array): string | Uint8Array {
  if (bytes.length > MAX_PSBT_TEXT) throw new PsbtError("too long to be a PSBT");
  const magic = [0x70, 0x73, 0x62, 0x74, 0xff];
  if (magic.every((b, i) => bytes[i] === b)) return bytes;
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/**
 * A copy of the same transaction with more signatures: the signatures of both. Refuses a different transaction.
 * Only b's valid signatures come in, and only for keys a has not signed yet: a forged signature cannot get in, and
 * cannot block the real one that comes later.
 */
export function combine(a: Transaction, b: Transaction): Transaction {
  if (a.id !== b.id) throw new PsbtError("a different transaction");
  const incoming = stripInvalid(b).tx;
  for (let n = 0; n < incoming.inputsLength; n++) {
    const held = a.getInput(n);
    const sigs = incoming.getInput(n).partialSig;
    if (sigs?.length) {
      const heldKeys = new Set((held.partialSig ?? []).map(([pk]) => hex.encode(pk)));
      const fresh = held.finalScriptWitness ? [] : sigs.filter(([pk]) => !heldKeys.has(hex.encode(pk)));
      setPartialSigs(incoming, n, fresh);
    }
    // Taproot: a Schnorr signature per key and leaf, and the key-path one.
    const tapSigs = incoming.getInput(n).tapScriptSig;
    if (tapSigs?.length) {
      const id = ([k]: TapSig) => hex.encode(k.pubKey) + hex.encode(k.leafHash);
      const heldKeys = new Set((held.tapScriptSig ?? []).map(id));
      const fresh = held.finalScriptWitness ? [] : tapSigs.filter((s) => !heldKeys.has(id(s)));
      setTapScriptSigs(incoming, n, fresh);
    }
    if (incoming.getInput(n).tapKeySig && (held.tapKeySig || held.finalScriptWitness)) incoming.updateInput(n, { tapKeySig: undefined }, true);
  }
  const out = a.clone();
  out.combine(incoming);
  // A finalised copy (Electrum finalises once its signature completes the spend) has dropped its key paths, and the
  // merge drops ours with them, as BIP 174's finaliser does. Without them the app cannot tell the coin is this
  // wallet's or whose signatures the witness holds, so keep a's: summarise still checks them against the coin's script.
  for (let n = 0; n < out.inputsLength; n++) {
    const held = a.getInput(n).bip32Derivation;
    if (held?.length && out.getInput(n).finalScriptWitness && !out.getInput(n).bip32Derivation?.length) {
      out.updateInput(n, { bip32Derivation: held }, true);
    }
    const heldTap = a.getInput(n).tapBip32Derivation;
    if (heldTap?.length && out.getInput(n).finalScriptWitness && !out.getInput(n).tapBip32Derivation?.length) {
      out.updateInput(n, { tapBip32Derivation: heldTap }, true);
    }
  }
  return out;
}

// ---------- signature checks ----------

type Sig = [Uint8Array, Uint8Array];
type TapSig = [{ pubKey: Uint8Array; leafHash: Uint8Array }, Uint8Array];

function setPartialSigs(tx: Transaction, n: number, sigs: Sig[]): void {
  tx.updateInput(n, { partialSig: undefined }, true);
  if (sigs.length) tx.updateInput(n, { partialSig: sigs }, true);
}

function setTapScriptSigs(tx: Transaction, n: number, sigs: TapSig[]): void {
  tx.updateInput(n, { tapScriptSig: undefined }, true);
  if (sigs.length) tx.updateInput(n, { tapScriptSig: sigs }, true);
}

/** OP_1 <32 bytes>: a Taproot output. */
const isTaproot = (script: Uint8Array) => script.length === 34 && script[0] === 0x51 && script[1] === 0x20;

/** Every input's coin, as BIP 341's signature hash commits to all of them; null if one is missing. */
function prevouts(tx: Transaction): { scripts: Uint8Array[]; amounts: bigint[] } | null {
  const scripts: Uint8Array[] = [];
  const amounts: bigint[] = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    const prev = prevoutOf(tx, i);
    if (!prev) return null;
    scripts.push(prev.script);
    amounts.push(prev.amount);
  }
  return { scripts, amounts };
}

/**
 * True if sig (64 bytes, SIGHASH_DEFAULT, or 65 with its sighash byte) is the x-only key's valid Schnorr signature of
 * input n (BIP 341): by the key path, or by the leaf `leafScript` (BIP 342).
 */
export function schnorrValid(tx: Transaction, n: number, xonly: Uint8Array, sig: Uint8Array, leafScript?: Uint8Array): boolean {
  if (xonly.length !== 32 || (sig.length !== 64 && sig.length !== 65) || (sig.length === 65 && sig[64] === 0)) return false;
  const all = prevouts(tx);
  if (!all) return false;
  try {
    const msg = tx.preimageWitnessV1(n, all.scripts, sig.length === 65 ? sig[64] : 0, all.amounts, -1, leafScript, TAPSCRIPT_LEAF);
    return schnorr.verify(sig.subarray(0, 64), msg, xonly);
  } catch {
    return false;
  }
}

/** True if the control block proves the Tapscript leaf is in the tree of the Taproot output key q (BIP 341). */
function controlBlockValid(cb: Uint8Array, script: Uint8Array, q: Uint8Array): boolean {
  if (cb.length < 33 || (cb.length - 33) % 32 || cb.length > 33 + 128 * 32 || (cb[0] & 0xfe) !== TAPSCRIPT_LEAF) return false;
  let h = tapLeafHash(script);
  for (let i = 33; i < cb.length; i += 32) h = tapBranch(h, cb.subarray(i, i + 32));
  try {
    const [key, parity] = btcUtils.taprootTweakPubkey(cb.subarray(1, 33), h);
    return same(key, q) && parity === (cb[0] & 1);
  } catch {
    return false;
  }
}

/** The Tapscript leaves of a PSBT input (PSBT_IN_TAP_LEAF_SCRIPT) that are in the coin's tree. */
function provenLeaves(tx: Transaction, n: number, q: Uint8Array): Uint8Array[] {
  return (tx.getInput(n).tapLeafScript ?? [])
    .filter(([cb, s]) => s[s.length - 1] === TAPSCRIPT_LEAF && controlBlockValid(TaprootControlBlock.encode(cb), s.subarray(0, -1), q))
    .map(([, s]) => s.subarray(0, -1));
}

/**
 * A finalised Taproot input checked against its coin: a key-path signature by the output key, or a script path
 * whose control block proves its leaf and whose stack runs it (Tapscript). An annex is refused. Null if it does not spend.
 */
function finalCheckTaproot(tx: Transaction, n: number, w: Uint8Array[], q: Uint8Array): Signed[] | null {
  if (tx.getInput(n).finalScriptSig?.length) return null;
  if (w.length >= 2 && w[w.length - 1][0] === 0x50) return null;
  if (w.length === 1) return schnorrValid(tx, n, q, w[0]) ? [{ pubkey: q, sig: w[0], keyPath: true }] : null;
  if (w.length < 2) return null;
  const script = w[w.length - 2];
  if (!controlBlockValid(w[w.length - 1], script, q)) return null;
  return runWitness(w.slice(0, -2), script, {
    tap: true,
    checkSig: (pubkey, sig) => schnorrValid(tx, n, pubkey, sig, script),
    ...timelocks(tx, n),
  });
}

/** The coin an input spends, from witness_utxo, else non_witness_utxo. */
function prevoutOf(tx: Transaction, n: number): { script: Uint8Array; amount: bigint } | null {
  const input = tx.getInput(n);
  if (input.witnessUtxo) return input.witnessUtxo;
  const prev = input.nonWitnessUtxo?.outputs[input.index!];
  return prev ? { script: prev.script, amount: prev.amount } : null;
}

/** True if the witness script is the one the coin's script locks to (P2WSH or P2SH-P2WSH). */
function locks(witnessScript: Uint8Array, script: Uint8Array): boolean {
  const wsh = p2wsh({ type: "unknown", script: witnessScript } as never);
  return same(wsh.script, script) || same(p2sh(wsh).script, script);
}

/** The keys and threshold of a multisig witness script, or null if it is not one. */
function multisigKeys(witnessScript: Uint8Array): { m: number; pubkeys: Uint8Array[] } | null {
  try {
    const d = OutScript.decode(witnessScript);
    return d.type === "ms" ? { m: d.m, pubkeys: d.pubkeys } : null;
  } catch {
    return null;
  }
}

/** True if sig (DER + sighash byte) is pubkey's valid signature of input n, spending amount under witnessScript (BIP 143). */
export function signatureValid(tx: Transaction, n: number, pubkey: Uint8Array, sig: Uint8Array, witnessScript: Uint8Array, amount: bigint): boolean {
  if (sig.length < 9) return false;
  try {
    const hash = tx.preimageWitnessV0(n, witnessScript, sig[sig.length - 1], amount);
    return secp256k1.verify(sig.subarray(0, -1), hash, pubkey, { prehash: false, format: "der" });
  } catch {
    return false;
  }
}

/**
 * The keys (indexes into pubkeys) whose signatures a finalised multisig witness carries, checked the way
 * OP_CHECKMULTISIG does; null if the witness would not spend the coin.
 */
function finalSigners(tx: Transaction, n: number, witness: Uint8Array[], witnessScript: Uint8Array, pubkeys: Uint8Array[], m: number, amount: bigint): Signed[] | null {
  if (witness.length !== m + 2 || witness[0].length !== 0 || !same(witness[witness.length - 1], witnessScript)) return null;
  const signers: Signed[] = [];
  let k = 0;
  for (const sig of witness.slice(1, -1)) {
    while (k < pubkeys.length && !signatureValid(tx, n, pubkeys[k], sig, witnessScript, amount)) k++;
    if (k === pubkeys.length) return null;
    signers.push({ pubkey: pubkeys[k++], sig });
  }
  return signers;
}

/** A signature a witness carries; keyPath: a Taproot key-path one, pubkey the output key. */
type Signed = { pubkey: Uint8Array; sig: Uint8Array; keyPath?: boolean };

/** What a transaction's input meets of the relative and absolute timelocks (BIP 68, 112, 65). */
function timelocks(tx: Transaction, n: number): { older: (lock: number) => boolean; after: (lock: number) => boolean } {
  const sequence = tx.getInput(n).sequence ?? 0xffffffff;
  return { older: (lock) => olderMet(lock, sequence, tx.version), after: (lock) => afterMet(lock, tx.lockTime, sequence) };
}

/**
 * A finalised input checked against its coin: the witness script (the given one, else the witness's own) must be the
 * one the coin locks to, the P2SH wrapper must match, and the signatures must spend it: a multisig witness the way
 * OP_CHECKMULTISIG reads it, any other (a miniscript one) run through miniscript.ts's interpreter. The signatures with
 * their keys, or null.
 */
function finalCheck(tx: Transaction, n: number, expected?: Uint8Array): Signed[] | null {
  const input = tx.getInput(n);
  const w = input.finalScriptWitness;
  const prev = prevoutOf(tx, n);
  if (w && prev && isTaproot(prev.script)) return finalCheckTaproot(tx, n, w, prev.script.subarray(2));
  const ws = expected ?? w?.[w.length - 1];
  if (!w || !prev || !ws || !locks(ws, prev.script)) return null;
  const wsh = p2wsh({ type: "unknown", script: ws } as never);
  const scriptSig = input.finalScriptSig ?? new Uint8Array();
  const wantSig = same(wsh.script, prev.script) ? new Uint8Array() : Uint8Array.of(wsh.script.length, ...wsh.script);
  if (!same(scriptSig, wantSig)) return null;
  const ms = multisigKeys(ws);
  if (ms) return finalSigners(tx, n, w, ws, ms.pubkeys, ms.m, prev.amount);
  if (!same(w[w.length - 1], ws)) return null;
  return runWitness(w.slice(0, -1), ws, {
    checkSig: (pubkey, sig) => signatureValid(tx, n, pubkey, sig, ws, prev.amount),
    ...timelocks(tx, n),
  });
}

/**
 * A copy without the signatures that do not check out: a partial signature by a key outside the input's witness
 * script, or one that does not verify; a finalised input whose witness would not spend the coin goes back to unsigned.
 * Read against the PSBT's own witness script and coin: the wallet's view is summarise's.
 */
export function stripInvalid(tx: Transaction): { tx: Transaction; dropped: number } {
  const out = tx.clone();
  let dropped = 0;
  for (let n = 0; n < out.inputsLength; n++) {
    const input = out.getInput(n);
    const prev = prevoutOf(out, n);
    if (input.finalScriptWitness) {
      if (!finalCheck(out, n)) {
        out.updateInput(n, { finalScriptWitness: undefined, finalScriptSig: undefined }, true);
        dropped++;
      }
      continue;
    }
    if (prev && isTaproot(prev.script)) {
      // A Taproot input: the key-path signature must be the output key's, a leaf's must be by a key in a leaf the
      // PSBT proves is in the coin's tree.
      const q = prev.script.subarray(2);
      if (input.tapKeySig && !schnorrValid(out, n, q, input.tapKeySig)) {
        out.updateInput(n, { tapKeySig: undefined }, true);
        dropped++;
      }
      const tapSigs = input.tapScriptSig ?? [];
      if (tapSigs.length) {
        const leaves = provenLeaves(out, n, q);
        const valid = tapSigs.filter(([{ pubKey, leafHash }, sig]) => {
          const leaf = leaves.find((l) => same(tapLeafHash(l), leafHash));
          return !!leaf && scriptHasKey(leaf, pubKey) && schnorrValid(out, n, pubKey, sig, leaf);
        });
        if (valid.length !== tapSigs.length) {
          dropped += tapSigs.length - valid.length;
          setTapScriptSigs(out, n, valid);
        }
      }
    }
    const sigs = input.partialSig ?? [];
    if (!sigs.length) continue;
    const ws = input.witnessScript;
    const ok = !!ws && !!prev && locks(ws, prev.script);
    const ms = ok ? multisigKeys(ws!) : null;
    const inScript = (pk: Uint8Array) => (ms ? ms.pubkeys.some((k) => same(k, pk)) : ok && scriptHasKey(ws!, pk));
    const valid = sigs.filter(([pk, sig]) => inScript(pk) && signatureValid(out, n, pk, sig, ws!, prev!.amount));
    if (valid.length !== sigs.length) {
      dropped += sigs.length - valid.length;
      setPartialSigs(out, n, valid);
    }
  }
  return { tx: out, dropped };
}

export type OutputKind = "external" | "change" | "receive" | "fake-change";

export interface OutputInfo {
  amount: bigint;
  /** The address, or "OP_RETURN"/"script" for outputs without one. */
  address: string;
  kind: OutputKind;
  /** For change/receive: the address's place in the wallet. */
  path?: { branch: number; index: number };
}

export interface InputInfo {
  /** txid:vout of the coin spent. */
  outpoint: string;
  amount: bigint | null;
  mine: boolean;
  /** Fingerprints of the co-signers whose signature this input holds. */
  signedBy: string[];
  final: boolean;
}

export interface Summary {
  txid: string;
  inputs: InputInfo[];
  outputs: OutputInfo[];
  /** Null when an input's amount is missing from the PSBT. */
  fee: bigint | null;
  /** Estimated size once fully signed. */
  vsize: number;
  /** Signatures still missing on the input that has the fewest. 0: ready to finalise. */
  missing: number;
  /** Fingerprints of the co-signers who signed every input. */
  signers: string[];
  complete: boolean;
  /** Reasons not to sign or send, in plain words; empty when none. */
  warnings: Warning[];
}

export type Warning =
  | { k: "foreign-input"; n: number }
  | { k: "fake-change"; n: number }
  | { k: "no-amount"; n: number }
  | { k: "amount-mismatch"; n: number }
  | { k: "sighash"; n: number }
  | { k: "high-fee" }
  | { k: "no-change-back" }
  /** A miniscript (Liana) spend whose inputs open a recovery path: the timelock, in blocks, of the longest one open. */
  | { k: "recovery-path"; blocks: number };

type Derivation = [Uint8Array, { fingerprint: number; path: number[] }][];
type TapDerivation = [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }][];

/** An input's or output's key paths: segwit v0's (PSBT_IN_BIP32_DERIVATION) and Taproot's (PSBT_IN_TAP_BIP32_DERIVATION). */
const derivations = (x: { bip32Derivation?: Derivation; tapBip32Derivation?: TapDerivation }): Derivation => [
  ...(x.bip32Derivation ?? []),
  ...(x.tapBip32Derivation ?? []).map(([pk, { der }]): Derivation[number] => [pk, der]),
];

const fp = (n: number) => (n >>> 0).toString(16).padStart(8, "0");

/** The wallet address (branch, index) a PSBT derivation points to, if it is one of this wallet's keys and paths. */
function placeOf(wallet: Wallet, derivation: Derivation | undefined): { branch: number; index: number } | null {
  for (const [, { fingerprint, path }] of derivation ?? []) {
    // A miniscript wallet can hold one co-signer's key several times, each at its own steps.
    for (const key of wallet.keys) {
      if (key.fingerprint !== fp(fingerprint) || path.length !== key.origin.length + key.steps.length) continue;
      if (!key.origin.every((s, i) => path[i] === s)) continue;
      let branch = -1;
      let index = -1;
      const ok = key.steps.every((step, i) => {
        const v = path[key.origin.length + i];
        if (step === "branch") branch = v;
        else if (step === "index") index = v;
        else return v === step;
        return v < 0x80000000;
      });
      if (!ok) continue;
      if (branch === key.branches.receive) return { branch: wallet.branches.receive, index };
      if (branch === key.branches.change) return { branch: wallet.branches.change, index };
    }
  }
  return null;
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export function addressOf(script: Uint8Array, network: Network): string {
  try {
    const decoded = OutScript.decode(script);
    if (decoded.type === "unknown") return "script";
    return Address(NETWORKS[network]).encode(decoded);
  } catch {
    return script[0] === 0x6a ? "OP_RETURN" : "script";
  }
}

const varint = (n: number) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);

/**
 * Bytes of one wallet input once signed: [non-witness, witness]. Signatures counted at 72 bytes, the most they take.
 * A miniscript input is counted as the smallest spend its timelocks allow, with every key signing.
 */
function inputSize(wallet: Wallet, tx: Transaction, n: number): [number, number] {
  const base = 41 + (wallet.script === "sh-wsh" ? 35 : 0);
  if (wallet.taproot) return [base, taprootWitnessSize(wallet, tx, n)];
  if (wallet.policy) {
    const key = Uint8Array.of(2, ...new Uint8Array(32));
    const ws = compile(wallet.policy, wallet.keys.map(() => key));
    const items = satisfaction(wallet.policy, { pubkey: () => key, sig: () => new Uint8Array(72), ...timelocks(tx, n) }) ??
      satisfaction(wallet.policy, { pubkey: () => key, sig: () => new Uint8Array(72), older: () => true, after: () => true }) ??
      [];
    return [base, varint(items.length + 1) + items.reduce((s, i) => s + varint(i.length) + i.length, 0) + varint(ws.length) + ws.length];
  }
  const ws = 3 + 34 * wallet.keys.length;
  const witness = varint(wallet.threshold + 2) + 1 + wallet.threshold * 73 + varint(ws) + ws;
  return [base, witness];
}

const witnessSize = (w: Uint8Array[]) => varint(w.length) + w.reduce((s, i) => s + varint(i.length) + i.length, 0);

/**
 * The smallest script-path witness (stack, leaf, control block) the signatures `sig(leaf, key)` and the input's
 * timelocks satisfy, among the leaves `use` allows; the first in the descriptor's order on a tie. Null if none.
 */
function cheapestLeaf(addr: TaprootAddress, sig: (leaf: number, key: number) => Uint8Array | undefined, lock: ReturnType<typeof timelocks>, use = (_l: number) => true): Uint8Array[] | null {
  let best: Uint8Array[] | null = null;
  addr.leaves.forEach((leaf, l) => {
    if (!use(l)) return;
    const items = satisfaction(leaf.ms, { pubkey: (k) => addr.xonly[k], sig: (k) => sig(l, k), ...lock });
    if (!items) return;
    const w = [...items, leaf.script, leaf.controlBlock];
    if (!best || witnessSize(w) < witnessSize(best)) best = w;
  });
  return best;
}

/** The signature a Taproot input holds by key `k` in leaf `l`. */
function tapSigOf(tx: Transaction, n: number, addr: TaprootAddress) {
  const sigs = tx.getInput(n).tapScriptSig ?? [];
  return (l: number, k: number) => sigs.find(([key]) => same(key.pubKey, addr.xonly[k]) && same(key.leafHash, addr.leaves[l].leafHash))?.[1];
}

/**
 * A Taproot input's witness bytes once signed: what finalise will make of the signatures it already has, if they are
 * enough; else the key path if the wallet has one and no recovery timelock is open; else the smallest leaf with every
 * key signing, among the recovery leaves whose timelock is open if one is (the reason for the spend), else among the
 * leaves the timelocks allow. Signatures at 64 bytes (65 if the PSBT asks for a sighash type).
 */
function taprootWitnessSize(wallet: Wallet, tx: Transaction, n: number): number {
  const input = tx.getInput(n);
  const place = placeOf(wallet, derivations(input));
  // The sizes are the same at every address: keys are 32 bytes, the tree's shape is the wallet's.
  const addr = deriveTaproot(wallet, place?.branch ?? wallet.branches.receive, place?.index ?? 0);
  const sigLen = input.sighashType ? 65 : 64;
  if (input.tapKeySig && addr.keyPath) return witnessSize([input.tapKeySig]);
  const lock = timelocks(tx, n);
  const have = place ? cheapestLeaf(addr, tapSigOf(tx, n, addr), lock) : null;
  if (have) return witnessSize(have);
  const recovery = addr.leaves.map((leaf) => olderLocks(leaf.ms).some(lock.older));
  if (addr.keyPath && !recovery.some(Boolean)) return witnessSize([new Uint8Array(sigLen)]);
  const all = () => new Uint8Array(sigLen);
  const w = cheapestLeaf(addr, all, lock, (l) => !recovery.some(Boolean) || recovery[l]) ??
    cheapestLeaf(addr, all, { older: () => true, after: () => true });
  return w ? witnessSize(w) : witnessSize([new Uint8Array(sigLen)]);
}

function estimateVsize(tx: Transaction, wallet: Wallet): number {
  let base = 4 + 4 + varint(tx.inputsLength) + varint(tx.outputsLength);
  let witness = 2;
  for (let i = 0; i < tx.outputsLength; i++) {
    const s = tx.getOutput(i).script!;
    base += 8 + varint(s.length) + s.length;
  }
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    if (input.finalScriptWitness) {
      const w = input.finalScriptWitness;
      witness += varint(w.length) + w.reduce((n, item) => n + varint(item.length) + item.length, 0);
      const ss = input.finalScriptSig?.length ?? 0;
      base += 40 + varint(ss) + ss;
    } else {
      const [ib, iw] = inputSize(wallet, tx, i);
      base += ib;
      witness += iw;
    }
  }
  return Math.ceil((base * 4 + witness) / 4);
}

/** A fee rate this far over what any mempool has needed is a mistake or an attack. */
const HIGH_FEE_RATE = 1000n;

export function summarise(tx: Transaction, wallet: Wallet, network: Network): Summary {
  const warnings: Warning[] = [];
  const inputs: InputInfo[] = [];
  /** Per input, the signatures still missing (0 once final). */
  const short: number[] = [];
  let totalIn: bigint | null = 0n;
  for (let n = 0; n < tx.inputsLength; n++) {
    const input = tx.getInput(n);
    let amount: bigint | null = null;
    let script: Uint8Array | undefined;
    if (input.witnessUtxo) {
      amount = input.witnessUtxo.amount;
      script = input.witnessUtxo.script;
    }
    const prev = input.nonWitnessUtxo?.outputs[input.index!];
    if (prev) {
      if (amount !== null && (prev.amount !== amount || !same(prev.script, script!))) warnings.push({ k: "amount-mismatch", n });
      amount ??= prev.amount;
      script ??= prev.script;
    }
    if (amount === null) {
      warnings.push({ k: "no-amount", n });
      totalIn = null;
    } else if (totalIn !== null) totalIn += amount;
    const place = placeOf(wallet, derivations(input));
    const mine = !!place && !!script && same(deriveScript(wallet, place.branch, place.index).script, script);
    if (!mine) warnings.push({ k: "foreign-input", n });
    // Who signed, read against the wallet: a signature counts only if it is by one of the keys the descriptor derives
    // for this input, and verifies. The PSBT's own key labels are not trusted.
    const signedBy: string[] = [];
    /** Indexes into wallet.keys of the keys whose valid signatures this input holds. */
    const signedKeys = new Set<number>();
    let final = false;
    if (wallet.taproot) {
      const t = mine && amount !== null ? taprootInput(tx, n, wallet, place!, warnings) : null;
      if (t) {
        signedBy.push(...t.signedBy);
        final = t.final;
      }
      short.push(t ? t.missing : wallet.threshold);
    } else if (input.finalScriptWitness) {
      // A finaliser (Bitcoin Core) drops the key paths, so a finalised input is checked against its own witness
      // script; when the paths are still there it must also be this wallet's script.
      const pubkeys = mine ? derivePubkeys(wallet, place!.branch, place!.index) : [];
      const done = finalCheck(tx, n, mine ? deriveScript(wallet, place!.branch, place!.index).witnessScript : undefined);
      if (done) {
        final = true;
        for (const { pubkey, sig } of done) {
          const at = pubkeys.findIndex((p) => same(p, pubkey));
          if (at >= 0) signedBy.push(wallet.keys[at].fingerprint);
          if (sig[sig.length - 1] !== 0x01) warnings.push({ k: "sighash", n });
        }
      }
    } else if (mine && amount !== null) {
      const pubkeys = derivePubkeys(wallet, place!.branch, place!.index);
      const { witnessScript } = deriveScript(wallet, place!.branch, place!.index);
      for (const [pk, sig] of input.partialSig ?? []) {
        const i = pubkeys.findIndex((p) => same(p, pk));
        if (i < 0 || !signatureValid(tx, n, pk, sig, witnessScript, amount)) continue;
        signedKeys.add(i);
        signedBy.push(wallet.keys[i].fingerprint);
        if (sig[sig.length - 1] !== 0x01) warnings.push({ k: "sighash", n });
      }
    }
    if (wallet.taproot) {
      // Counted above.
    } else if (final) short.push(0);
    else if (wallet.policy) {
      // The fewest signatures that complete any spending path this input's timelocks open.
      const need = missingSignatures(wallet.policy, (i) => signedKeys.has(i), timelocks(tx, n));
      short.push(Number.isFinite(need) ? need : missingSignatures(wallet.policy, (i) => signedKeys.has(i), { older: () => true, after: () => true }));
    } else short.push(Math.max(0, wallet.threshold - new Set(signedBy).size));
    if (mine && wallet.policy) {
      const open = olderLocks(wallet.policy).filter(timelocks(tx, n).older);
      if (open.length) warnings.push({ k: "recovery-path", blocks: Math.max(...open) });
    }
    // SIGHASH_ALL; in Taproot also SIGHASH_DEFAULT (0), which signs the same.
    if (input.sighashType !== undefined && input.sighashType !== 1 && !(wallet.taproot && input.sighashType === 0)) warnings.push({ k: "sighash", n });
    inputs.push({
      outpoint: `${hex.encode(input.txid!)}:${input.index}`,
      amount,
      mine,
      signedBy: [...new Set(signedBy)],
      final,
    });
  }

  const outputs: OutputInfo[] = [];
  let totalOut = 0n;
  for (let n = 0; n < tx.outputsLength; n++) {
    const output = tx.getOutput(n);
    const script = output.script!;
    totalOut += output.amount!;
    const info: OutputInfo = { amount: output.amount!, address: addressOf(script, network), kind: "external" };
    const place = placeOf(wallet, derivations(output));
    if (place) {
      if (same(deriveScript(wallet, place.branch, place.index).script, script)) {
        info.kind = place.branch === wallet.branches.change ? "change" : "receive";
        info.path = place;
      } else {
        info.kind = "fake-change";
        warnings.push({ k: "fake-change", n });
      }
    }
    outputs.push(info);
  }

  const fee = totalIn === null ? null : totalIn - totalOut;
  const recoveries = warnings.filter((w) => w.k === "recovery-path");
  if (recoveries.length > 1) {
    const blocks = Math.max(...recoveries.map((w) => w.blocks));
    for (let i = warnings.length - 1; i >= 0; i--) if (warnings[i].k === "recovery-path") warnings.splice(i, 1);
    warnings.unshift({ k: "recovery-path", blocks });
  }
  // One warning per kind and place, however many signatures carry it.
  const seen = new Set<string>();
  for (let i = warnings.length - 1; i >= 0; i--) {
    const key = JSON.stringify(warnings[i]);
    if (seen.has(key)) warnings.splice(i, 1);
    else seen.add(key);
  }

  const vsize = estimateVsize(tx, wallet);
  if (fee !== null && (fee < 0n || fee > HIGH_FEE_RATE * BigInt(vsize) || (totalIn! > 0n && fee * 10n > totalIn!))) warnings.push({ k: "high-fee" });
  const spendsMine = inputs.some((i) => i.mine);
  const outsideOnly = outputs.every((o) => o.kind === "external" || o.kind === "fake-change");
  if (spendsMine && outsideOnly && outputs.length > 1) warnings.push({ k: "no-change-back" });

  const missing = Math.max(0, ...short);
  const signers = fingerprints(wallet)
    // A finalised input names only the keys whose signatures its witness carries (checked above), never all of them.
    .filter((f) => inputs.length > 0 && inputs.every((i) => i.signedBy.includes(f)));
  return { txid: tx.id, inputs, outputs, fee, vsize, missing, signers, complete: missing === 0 && inputs.length > 0, warnings };
}

/** A Taproot signature signing as SIGHASH_ALL does: 64 bytes (SIGHASH_DEFAULT), or 65 ending in 0x01. */
const tapSighashAll = (sig: Uint8Array) => sig.length === 64 || sig[64] === 0x01;

/**
 * A Taproot (Liana) wallet's input, read against the wallet's address: who signed (by the key path, or in which
 * leaf: a signature counts only in its own leaf), and the fewest signatures still missing over the key path and every
 * leaf the timelocks open (over every leaf if none is open yet). A recovery leaf whose timelock is open warns.
 */
function taprootInput(tx: Transaction, n: number, wallet: Wallet, place: { branch: number; index: number }, warnings: Warning[]): { signedBy: string[]; final: boolean; missing: number } {
  const t = wallet.taproot!;
  const addr = deriveTaproot(wallet, place.branch, place.index);
  const input = tx.getInput(n);
  const q = addr.script.subarray(2);
  const lock = timelocks(tx, n);
  const open = t.leaves.flatMap(olderLocks).filter(lock.older);
  if (open.length) warnings.push({ k: "recovery-path", blocks: Math.max(...open) });
  const signedBy: string[] = [];
  const keyAt = (pk: Uint8Array) => addr.xonly.findIndex((p) => same(p, pk));
  if (input.finalScriptWitness) {
    // The coin is this wallet's address, so a witness that spends it is this wallet's.
    const done = finalCheck(tx, n);
    if (done) {
      for (const { pubkey, sig, keyPath } of done) {
        const at = keyPath ? t.internal! : keyAt(pubkey);
        if (at !== null && at >= 0) signedBy.push(wallet.keys[at].fingerprint);
        if (!tapSighashAll(sig)) warnings.push({ k: "sighash", n });
      }
      return { signedBy, final: true, missing: 0 };
    }
  }
  let keySigned = false;
  if (addr.keyPath && input.tapKeySig && schnorrValid(tx, n, q, input.tapKeySig)) {
    keySigned = true;
    signedBy.push(wallet.keys[t.internal!].fingerprint);
    if (!tapSighashAll(input.tapKeySig)) warnings.push({ k: "sighash", n });
  }
  const perLeaf = addr.leaves.map(() => new Set<number>());
  for (const [{ pubKey, leafHash }, sig] of input.finalScriptWitness ? [] : input.tapScriptSig ?? []) {
    const l = addr.leaves.findIndex((leaf) => same(leaf.leafHash, leafHash));
    const k = keyAt(pubKey);
    if (l < 0 || k < 0 || !scriptHasKey(addr.leaves[l].script, pubKey)) continue;
    if (!schnorrValid(tx, n, pubKey, sig, addr.leaves[l].script)) continue;
    perLeaf[l].add(k);
    signedBy.push(wallet.keys[k].fingerprint);
    if (!tapSighashAll(sig)) warnings.push({ k: "sighash", n });
  }
  const need = (ctx: Pick<ReturnType<typeof timelocks>, "older" | "after">) =>
    Math.min(addr.keyPath ? (keySigned ? 0 : 1) : Infinity, ...addr.leaves.map((leaf, l) => missingSignatures(leaf.ms, (k) => perLeaf[l].has(k), ctx)));
  const missing = need(lock);
  return { signedBy, final: false, missing: Number.isFinite(missing) ? missing : need({ older: () => true, after: () => true }) };
}

/**
 * The signed transaction, ready for any wallet or node to broadcast. Throws if signatures are missing. A miniscript
 * (Liana) wallet's inputs need the wallet: their witness is the smallest one the signatures and timelocks satisfy.
 */
export function finalise(tx: Transaction, wallet?: Wallet): string {
  const out = stripInvalid(tx).tx;
  try {
    // An input a wallet already finalised (Electrum does, once its signature completes the spend) keeps its witness;
    // stripInvalid has checked it.
    for (let n = 0; n < out.inputsLength; n++) {
      const input = out.getInput(n);
      if (input.finalScriptWitness) continue;
      if (wallet?.taproot) finaliseTaproot(out, n, wallet);
      else if (wallet?.policy) finaliseMiniscript(out, n, wallet);
      else out.finalizeIdx(n);
    }
    return hex.encode(out.extract());
  } catch (e) {
    throw new PsbtError(`cannot finalise yet (${(e as Error).message})`);
  }
}

/** Finalises a miniscript wallet's input n: its witness from the PSBT's signatures, checked by running it. */
function finaliseMiniscript(tx: Transaction, n: number, wallet: Wallet): void {
  const input = tx.getInput(n);
  const place = placeOf(wallet, derivations(input));
  const prev = prevoutOf(tx, n);
  if (!place || !prev) throw new PsbtError(`input ${n + 1} is not this wallet's`);
  const { script, witnessScript } = deriveScript(wallet, place.branch, place.index);
  if (!same(script, prev.script)) throw new PsbtError(`input ${n + 1} is not this wallet's`);
  const pubkeys = derivePubkeys(wallet, place.branch, place.index);
  const sigs = input.partialSig ?? [];
  const items = satisfaction(wallet.policy!, {
    pubkey: (k) => pubkeys[k],
    sig: (k) => sigs.find(([pk]) => same(pk, pubkeys[k]))?.[1],
    ...timelocks(tx, n),
  });
  if (!items) throw new PsbtError(`input ${n + 1} has not enough signatures`);
  const witness = [...items, witnessScript];
  const wsh = p2wsh({ type: "unknown", script: witnessScript } as never);
  const scriptSig = wallet.script === "sh-wsh" ? Uint8Array.of(wsh.script.length, ...wsh.script) : undefined;
  tx.updateInput(n, { finalScriptWitness: witness, ...(scriptSig ? { finalScriptSig: scriptSig } : {}) }, true);
  if (!finalCheck(tx, n, witnessScript)) throw new PsbtError(`input ${n + 1}: the witness does not spend the coin`);
  // As BIP 174's finaliser does: the signing data goes once the witness is in.
  tx.updateInput(n, { partialSig: undefined, witnessScript: undefined, bip32Derivation: undefined, sighashType: undefined }, true);
}

/**
 * Finalises a Taproot wallet's input n: by the key path if it has the internal key's signature (the cheapest spend),
 * else by the smallest leaf the signatures and timelocks satisfy, its witness the leaf's stack, the leaf and its
 * control block. Checked by running it.
 */
function finaliseTaproot(tx: Transaction, n: number, wallet: Wallet): void {
  const input = tx.getInput(n);
  const place = placeOf(wallet, derivations(input));
  const prev = prevoutOf(tx, n);
  if (!place || !prev) throw new PsbtError(`input ${n + 1} is not this wallet's`);
  const addr = deriveTaproot(wallet, place.branch, place.index);
  if (!same(addr.script, prev.script)) throw new PsbtError(`input ${n + 1} is not this wallet's`);
  const witness = addr.keyPath && input.tapKeySig ? [input.tapKeySig] : cheapestLeaf(addr, tapSigOf(tx, n, addr), timelocks(tx, n));
  if (!witness) throw new PsbtError(`input ${n + 1} has not enough signatures`);
  tx.updateInput(n, { finalScriptWitness: witness }, true);
  if (!finalCheck(tx, n)) throw new PsbtError(`input ${n + 1}: the witness does not spend the coin`);
  tx.updateInput(n, {
    partialSig: undefined, bip32Derivation: undefined, sighashType: undefined, tapKeySig: undefined, tapScriptSig: undefined,
    tapLeafScript: undefined, tapBip32Derivation: undefined, tapInternalKey: undefined, tapMerkleRoot: undefined,
  }, true);
}
