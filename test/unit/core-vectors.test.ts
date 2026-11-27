/**
 * Bitcoin Core's PSBT test vectors (test/functional/data/rpc_psbt.json at v30.2, MIT; most are the BIP 174 vectors)
 * through this app's own read, signature check, merge and finalise path.
 *
 * The combiner and finalizer vectors are a 2-input transaction: input 0 is legacy P2SH 2-of-2 (not supported here: its
 * signatures are taken out as unverifiable), input 1 is P2SH-P2WSH 2-of-2 (supported: it must come out as Core's).
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { hex } from "@scure/base";
import type { Transaction } from "@scure/btc-signer";
import { combine, readPsbt, stripInvalid } from "../../src/psbt.ts";

const vectors = JSON.parse(readFileSync(new URL("../vectors/core-rpc_psbt.json", import.meta.url), "utf8")) as {
  valid: string[];
  invalid: string[];
  invalid_with_msg: [string, string][];
  combiner: { combine: string[]; result: string }[];
  finalizer: { finalize: string; result: string }[];
};

const sigs = (tx: Transaction, n: number): string[] =>
  (tx.getInput(n).partialSig ?? []).map(([pk, sig]) => `${hex.encode(pk)}:${hex.encode(sig)}`).sort();

const reads = (text: string): boolean => {
  try {
    readPsbt(text);
    return true;
  } catch {
    return false;
  }
};

describe("Bitcoin Core rpc_psbt.json", () => {
  test("reads every valid PSBT", () => {
    expect(vectors.valid.filter((p) => !reads(p))).toEqual([]);
  });

  test("refuses every invalid PSBT", () => {
    expect(vectors.invalid.filter(reads)).toEqual([]);
    expect(vectors.invalid_with_msg.filter(([p]) => reads(p)).map(([, why]) => why)).toEqual([]);
  });

  test("merges the combiner's signatures as Core does on the P2SH-P2WSH input", () => {
    const { combine: [a, b], result } = vectors.combiner[0];
    const merged = combine(stripInvalid(readPsbt(a)).tx, readPsbt(b));
    const expected = readPsbt(result);
    expect(sigs(merged, 1)).toHaveLength(2);
    expect(sigs(merged, 1)).toEqual(sigs(expected, 1));
    // Legacy P2SH has no BIP 143 signature to check: out of scope, taken out.
    expect(sigs(merged, 0)).toEqual([]);
  });

  test("keeps Core's real signatures and finalises the P2SH-P2WSH input to Core's witness", () => {
    const { finalize, result } = vectors.finalizer[0];
    const { tx, dropped } = stripInvalid(readPsbt(finalize));
    expect(dropped).toBe(2); // the two legacy P2SH signatures on input 0
    expect(sigs(tx, 1)).toHaveLength(2);
    tx.finalizeIdx(1);
    expect(tx.getInput(1).finalScriptWitness).toEqual(readPsbt(result).getInput(1).finalScriptWitness);
    expect(tx.getInput(1).finalScriptSig).toEqual(readPsbt(result).getInput(1).finalScriptSig);
  });

  test("accepts Core's finalised P2SH-P2WSH witness as spending the coin", () => {
    // Input 0 is finalised as legacy P2SH (finalScriptSig only) and is not checked; input 1's witness must pass.
    expect(stripInvalid(readPsbt(vectors.finalizer[0].result)).dropped).toBe(0);
  });

  test("refuses the BIP 174 PSBT whose input key 0x0f is now BIP 370's PSBT_IN_OUTPUT_INDEX", () => {
    // Valid under BIP 174 alone (an unknown key with key data); @scure/btc-signer reads 0x0f as the v2 field.
    expect(reads(vectors.combiner[1].combine[0])).toBe(false);
  });
});
