/**
 * test/vectors/electrum.json (made by scripts/interop/electrum.mjs): Electrum's Multisig_Wallet as a co-signer of the
 * spend in signing.json. Core finalised every copy; the app must make the same transactions. Once its signature
 * completes the spend, Electrum hands out the raw transaction, not a PSBT; the app must say so plainly.
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { parseWallet } from "../../src/descriptor.ts";
import { combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";

const read = (name: string) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));
const v = read("signing.json");
const e = read("electrum.json") as Record<string, string>;
const wallet = parseWallet(v.descriptor);

describe("Electrum as a co-signer", () => {
  test("its signature passes the app's own check", () => {
    expect(stripInvalid(readPsbt(e.signedElectrum)).dropped).toBe(0);
    expect(summarise(readPsbt(e.signedElectrum), wallet, "regtest").signers).toEqual([v.fingerprints.drongo]);
  });

  // The second signature completes the spend, so Electrum finalises: the witness is in, the signatures and key paths
  // are gone. Merged into the copy the person sent out, the app reads the witness against this wallet's script.
  test.each([
    ["after the Trezor", () => v.signedTrezor, () => e.electrumOnTrezor, ["drongo", "trezor"]],
    ["after Core", () => v.signedCore, () => e.electrumOnCore, ["core", "trezor"]],
  ] as const)("finalised by Electrum %s, merged back: exactly the two who signed", (_, sent, back, who) => {
    expect(stripInvalid(readPsbt(back())).dropped).toBe(0);
    const merged = combine(readPsbt(sent()), readPsbt(back()));
    const s = summarise(merged, wallet, "regtest");
    expect(s.signers.sort()).toEqual(who.map((k) => v.fingerprints[k]).sort());
    expect(s.complete).toBe(true);
    expect(s.warnings).toEqual([]);
  });

  test("a finalised copy alone, without its key paths: complete, but no signer named and the coins not claimed", () => {
    const s = summarise(readPsbt(e.electrumOnTrezor), wallet, "regtest");
    expect(s.complete).toBe(true);
    expect(s.signers).toEqual([]);
    expect(s.warnings.map((w) => w.k)).toContain("foreign-input");
  });

  test("Core + Electrum, either order: the transaction Core mined", () => {
    expect(finalise(combine(readPsbt(v.signedCore), readPsbt(e.signedElectrum)))).toBe(v.final);
    expect(finalise(combine(readPsbt(e.signedElectrum), readPsbt(v.signedCore)))).toBe(v.final);
  });

  test("Electrum signing after the Trezor, or after Core: what Core and Electrum both finish", () => {
    expect(finalise(readPsbt(e.electrumOnTrezor))).toBe(e.electrumOnTrezorRaw);
    expect(finalise(readPsbt(e.electrumOnCore))).toBe(e.finalCoreElectrum);
    expect(e.electrumOnCoreRaw).toBe(e.finalCoreElectrum);
  });

  test("Electrum's finished transaction pasted in: a plain explanation, not 'not a PSBT'", () => {
    for (const raw of [e.electrumOnTrezorRaw, e.electrumOnCoreRaw, ` ${v.final}\n`]) {
      expect(() => readPsbt(raw)).toThrow(/^a finished, signed transaction, not a PSBT/);
    }
  });

  test("an unsigned raw transaction is not taken for a finished one", () => {
    const draft = readPsbt(v.unsigned).unsignedTx;
    expect(() => readPsbt(Buffer.from(draft).toString("hex"))).toThrow(/not a PSBT this app can read|not a PSBT:/);
    expect(() => readPsbt(Buffer.from(draft).toString("hex"))).not.toThrow(/finished/);
  });
});
