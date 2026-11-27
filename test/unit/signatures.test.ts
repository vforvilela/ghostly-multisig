/**
 * Signatures from the contact are untrusted: one that does not verify must not count, must not block the real one,
 * and must not end up in the signed transaction.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { derivePubkeys, parseWallet } from "../../src/descriptor";
import { combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt";

const fixture = (f: string) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8").trim();
const wallet = parseWallet(fixture("descriptor.txt"));
const tx = (f: string) => readPsbt(fixture(f));

/** A well-formed DER signature (r = s = 1) with SIGHASH_ALL that verifies for no key. */
const forgedSig = (): Uint8Array => {
  const sig = new Uint8Array(71);
  sig.set([0x30, 68, 2, 32, 1], 0);
  sig.set([2, 32, 1], 36);
  sig[70] = 0x01;
  return sig;
};
const keyOf = (t: Transaction, n: number) => t.getInput(n).partialSig![0][0];
/** The input's key that has not signed in t. */
const unsignedKey = (t: Transaction, n: number) => {
  const input = t.getInput(n);
  const signed = new Set(input.partialSig!.map(([pk]) => hex.encode(pk)));
  return input.bip32Derivation!.find(([pk]) => !signed.has(hex.encode(pk)))![0];
};
/** t with a forged signature by key(n) added to every input. */
function forge(t: Transaction, key: (t: Transaction, n: number) => Uint8Array): Transaction {
  const out = t.clone();
  for (let n = 0; n < out.inputsLength; n++) out.updateInput(n, { partialSig: [[key(t, n), forgedSig()]] }, true);
  return out;
}

describe("signatures", () => {
  it("keeps real signatures, complete or finalised", () => {
    for (const f of ["1-alice.psbt", "2-combined.psbt", "2-alice-bob.psbt"]) expect(stripInvalid(tx(f)).dropped).toBe(0);
    expect(summarise(tx("2-alice-bob.psbt"), wallet, "regtest").complete).toBe(true);
  });

  it("does not count a forged signature, and takes it out", () => {
    const forged = forge(tx("1-alice.psbt"), unsignedKey);
    const s = summarise(forged, wallet, "regtest");
    expect(s.missing).toBe(1);
    expect(s.complete).toBe(false);
    expect(s.signers).toHaveLength(1);
    expect(stripInvalid(forged).dropped).toBe(2);
    expect(() => finalise(forged)).toThrow();
    // Merged in from the contact, it does not get in either.
    expect(summarise(combine(tx("1-alice.psbt"), forged), wallet, "regtest").complete).toBe(false);
  });

  it("does not count a signature labelled as a co-signer's but by a key outside the script", () => {
    const alice = tx("1-alice.psbt");
    const evil = alice.clone();
    const outsider = derivePubkeys(wallet, 0, 99)[0];
    for (let n = 0; n < evil.inputsLength; n++) {
      const label = evil.getInput(n).bip32Derivation!.find(([pk]) => hex.encode(pk) === hex.encode(unsignedKey(alice, n)))![1];
      evil.updateInput(n, { bip32Derivation: [[outsider, label]], partialSig: [[outsider, alice.getInput(n).partialSig![0][1]]] }, true);
    }
    expect(summarise(evil, wallet, "regtest").complete).toBe(false);
    expect(summarise(combine(alice, evil), wallet, "regtest").signers).toHaveLength(1);
  });

  it("lets the real signature in after a forged one for the same key", () => {
    const bob = tx("1-bob.psbt");
    const held = combine(tx("1-alice.psbt"), forge(tx("1-alice.psbt"), (_, n) => keyOf(bob, n)));
    const merged = combine(held, bob);
    expect(summarise(merged, wallet, "regtest").complete).toBe(true);
    expect(finalise(merged)).toMatch(/^02000000/);
  });

  it("puts only real signatures in the signed transaction", () => {
    const both = tx("2-combined.psbt");
    const raw = finalise(forge(both, unsignedKey));
    const witness = Transaction.fromRaw(hex.decode(raw), { allowUnknownOutputs: true }).getInput(0).finalScriptWitness!;
    expect(witness.slice(1, -1).some((s) => hex.encode(s) === hex.encode(forgedSig()))).toBe(false);
    expect(raw).toBe(finalise(both));
  });

  it("turns a finalised input with a forged witness back to unsigned", () => {
    const final = tx("2-alice-bob.psbt");
    const evil = final.clone();
    const w = evil.getInput(0).finalScriptWitness!;
    evil.updateInput(0, { finalScriptWitness: [w[0], forgedSig(), w[2], w[3]] }, true);
    const s = summarise(evil, wallet, "regtest");
    expect(s.inputs[0].final).toBe(false);
    expect(s.complete).toBe(false);
    expect(stripInvalid(evil).dropped).toBe(1);
  });
});
