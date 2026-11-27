/**
 * What a PSBT does, read against the person's own wallet: where every satoshi goes, which output is really their change,
 * the fee, and how many of the co-signers have signed. Nothing here signs: signing stays in the person's coordinator and
 * hardware wallet, and their screen is the one to trust (see docs/design.md).
 */
import { Address, NETWORK, OutScript, TEST_NETWORK, Transaction, p2sh, p2wsh } from "@scure/btc-signer";
import { base64, hex } from "@scure/base";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { deriveScript, derivePubkeys, type Wallet } from "./descriptor.ts";

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
    if (!sigs?.length) continue;
    const heldKeys = new Set((held.partialSig ?? []).map(([pk]) => hex.encode(pk)));
    const fresh = held.finalScriptWitness ? [] : sigs.filter(([pk]) => !heldKeys.has(hex.encode(pk)));
    setPartialSigs(incoming, n, fresh);
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
  }
  return out;
}

// ---------- signature checks ----------

type Sig = [Uint8Array, Uint8Array];

function setPartialSigs(tx: Transaction, n: number, sigs: Sig[]): void {
  tx.updateInput(n, { partialSig: undefined }, true);
  if (sigs.length) tx.updateInput(n, { partialSig: sigs }, true);
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
function finalSigners(tx: Transaction, n: number, witness: Uint8Array[], witnessScript: Uint8Array, pubkeys: Uint8Array[], m: number, amount: bigint): number[] | null {
  if (witness.length !== m + 2 || witness[0].length !== 0 || !same(witness[witness.length - 1], witnessScript)) return null;
  const signers: number[] = [];
  let k = 0;
  for (const sig of witness.slice(1, -1)) {
    while (k < pubkeys.length && !signatureValid(tx, n, pubkeys[k], sig, witnessScript, amount)) k++;
    if (k === pubkeys.length) return null;
    signers.push(k++);
  }
  return signers;
}

/**
 * A finalised input checked against its coin: the witness script (the given one, else the witness's own) must be the
 * one the coin locks to, the P2SH wrapper must match, and the signatures must spend it. The signing keys (as
 * [pubkeys, indexes]) or null.
 */
function finalCheck(tx: Transaction, n: number, expected?: Uint8Array): { pubkeys: Uint8Array[]; signers: number[] } | null {
  const input = tx.getInput(n);
  const w = input.finalScriptWitness;
  const prev = prevoutOf(tx, n);
  const ws = expected ?? w?.[w.length - 1];
  if (!w || !prev || !ws || !locks(ws, prev.script)) return null;
  const wsh = p2wsh({ type: "unknown", script: ws } as never);
  const scriptSig = input.finalScriptSig ?? new Uint8Array();
  const wantSig = same(wsh.script, prev.script) ? new Uint8Array() : Uint8Array.of(wsh.script.length, ...wsh.script);
  if (!same(scriptSig, wantSig)) return null;
  const ms = multisigKeys(ws);
  const signers = ms && finalSigners(tx, n, w, ws, ms.pubkeys, ms.m, prev.amount);
  return signers ? { pubkeys: ms.pubkeys, signers } : null;
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
    const sigs = input.partialSig ?? [];
    if (!sigs.length) continue;
    const ws = input.witnessScript;
    const ms = ws && prev && locks(ws, prev.script) ? multisigKeys(ws) : null;
    const valid = sigs.filter(
      ([pk, sig]) => !!ms && ms.pubkeys.some((k) => same(k, pk)) && signatureValid(out, n, pk, sig, ws!, prev!.amount),
    );
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
  | { k: "no-change-back" };

type Derivation = [Uint8Array, { fingerprint: number; path: number[] }][];

const fp = (n: number) => (n >>> 0).toString(16).padStart(8, "0");

/** The wallet address (branch, index) a PSBT derivation points to, if it is one of this wallet's keys and paths. */
function placeOf(wallet: Wallet, derivation: Derivation | undefined): { branch: number; index: number } | null {
  for (const [, { fingerprint, path }] of derivation ?? []) {
    const key = wallet.keys.find((k) => k.fingerprint === fp(fingerprint));
    if (!key || path.length !== key.origin.length + key.steps.length) continue;
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
    if (ok && (branch === wallet.branches.receive || branch === wallet.branches.change)) return { branch, index };
  }
  return null;
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

function addressOf(script: Uint8Array, network: Network): string {
  try {
    const decoded = OutScript.decode(script);
    if (decoded.type === "unknown") return "script";
    return Address(NETWORKS[network]).encode(decoded);
  } catch {
    return script[0] === 0x6a ? "OP_RETURN" : "script";
  }
}

const varint = (n: number) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);

/** Bytes of one wallet input once signed: [non-witness, witness]. Signatures counted at 72 bytes, the most they take. */
function inputSize(wallet: Wallet): [number, number] {
  const ws = 3 + 34 * wallet.keys.length;
  const witness = varint(wallet.threshold + 2) + 1 + wallet.threshold * 73 + varint(ws) + ws;
  return [41 + (wallet.script === "sh-wsh" ? 35 : 0), witness];
}

function estimateVsize(tx: Transaction, wallet: Wallet): number {
  let base = 4 + 4 + varint(tx.inputsLength) + varint(tx.outputsLength);
  let witness = 2;
  for (let i = 0; i < tx.outputsLength; i++) {
    const s = tx.getOutput(i).script!;
    base += 8 + varint(s.length) + s.length;
  }
  const [ib, iw] = inputSize(wallet);
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    if (input.finalScriptWitness) {
      const w = input.finalScriptWitness;
      witness += varint(w.length) + w.reduce((n, item) => n + varint(item.length) + item.length, 0);
      const ss = input.finalScriptSig?.length ?? 0;
      base += 40 + varint(ss) + ss;
    } else {
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
    const place = placeOf(wallet, input.bip32Derivation as Derivation | undefined);
    const mine = !!place && !!script && same(deriveScript(wallet, place.branch, place.index).script, script);
    if (!mine) warnings.push({ k: "foreign-input", n });
    // Who signed, read against the wallet: a signature counts only if it is by one of the keys the descriptor derives
    // for this input, and verifies. The PSBT's own key labels are not trusted.
    const signedBy: string[] = [];
    let final = false;
    if (input.finalScriptWitness) {
      // A finaliser (Bitcoin Core) drops the key paths, so a finalised input is checked against its own witness
      // script; when the paths are still there it must also be this wallet's script.
      const pubkeys = mine ? derivePubkeys(wallet, place!.branch, place!.index) : [];
      const done = finalCheck(tx, n, mine ? deriveScript(wallet, place!.branch, place!.index).witnessScript : undefined);
      if (done) {
        final = true;
        for (const i of done.signers) {
          const at = pubkeys.findIndex((p) => same(p, done.pubkeys[i]));
          if (at >= 0) signedBy.push(wallet.keys[at].fingerprint);
        }
        for (const sig of input.finalScriptWitness.slice(1, -1)) if (sig[sig.length - 1] !== 0x01) warnings.push({ k: "sighash", n });
      }
    } else if (mine && amount !== null) {
      const pubkeys = derivePubkeys(wallet, place!.branch, place!.index);
      const { witnessScript } = deriveScript(wallet, place!.branch, place!.index);
      for (const [pk, sig] of input.partialSig ?? []) {
        const i = pubkeys.findIndex((p) => same(p, pk));
        if (i < 0 || !signatureValid(tx, n, pk, sig, witnessScript, amount)) continue;
        signedBy.push(wallet.keys[i].fingerprint);
        if (sig[sig.length - 1] !== 0x01) warnings.push({ k: "sighash", n });
      }
    }
    if (input.sighashType !== undefined && input.sighashType !== 1) warnings.push({ k: "sighash", n });
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
    const place = placeOf(wallet, output.bip32Derivation as Derivation | undefined);
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

  const counts = inputs.map((i) => (i.final ? wallet.threshold : i.signedBy.length));
  const missing = Math.max(0, ...counts.map((c) => wallet.threshold - c));
  const signers = wallet.keys
    .map((k) => k.fingerprint)
    // A finalised input names only the keys whose signatures its witness carries (checked above), never all of them.
    .filter((f) => inputs.length > 0 && inputs.every((i) => i.signedBy.includes(f)));
  return { txid: tx.id, inputs, outputs, fee, vsize, missing, signers, complete: missing === 0 && inputs.length > 0, warnings };
}

/** The signed transaction, ready for any wallet or node to broadcast. Throws if signatures are missing. */
export function finalise(tx: Transaction): string {
  const out = stripInvalid(tx).tx;
  try {
    // An input a wallet already finalised (Electrum does, once its signature completes the spend) keeps its witness;
    // stripInvalid has checked it.
    for (let n = 0; n < out.inputsLength; n++) if (!out.getInput(n).finalScriptWitness) out.finalizeIdx(n);
    return hex.encode(out.extract());
  } catch (e) {
    throw new PsbtError(`cannot finalise yet (${(e as Error).message})`);
  }
}
