/**
 * test/vectors/signing.json (made by scripts/interop/signing.mjs): a 2-of-3 P2WSH spend Bitcoin Core created and signed
 * with key A, Sparrow's drongo signed with key B, and a Trezor Model T emulator signed with key C through HWI. Core
 * finalised every pairing and mined Core + drongo. The app, as combiner and finaliser, must give the very transaction
 * Core made from the same copies, whichever order they come in.
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { parseWallet } from "../../src/descriptor.ts";
import { combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";

const v = JSON.parse(readFileSync(new URL("../vectors/signing.json", import.meta.url), "utf8")) as {
  descriptor: string;
  fingerprints: { core: string; drongo: string; trezor: string };
  payee: string;
  unsigned: string;
  signedCore: string;
  signedDrongo: string;
  signedBoth: string;
  signedTrezor: string;
  final: string;
  finalCoreTrezor: string;
  finalDrongoTrezor: string;
  finalAll: string;
  txid: string;
};
const wallet = parseWallet(v.descriptor);

describe("Core and Sparrow (drongo) co-signing", () => {
  test("Core then drongo: the transaction Core mined", () => {
    expect(finalise(combine(readPsbt(v.signedCore), readPsbt(v.signedDrongo)))).toBe(v.final);
  });

  test("drongo then Core: the same transaction", () => {
    expect(finalise(combine(readPsbt(v.signedDrongo), readPsbt(v.signedCore)))).toBe(v.final);
  });

  test("a copy merged twice changes nothing", () => {
    const twice = combine(combine(readPsbt(v.signedCore), readPsbt(v.signedCore)), readPsbt(v.signedDrongo));
    expect(finalise(twice)).toBe(v.final);
  });

  test("drongo signing Core's copy (the usual relay): the same transaction", () => {
    expect(finalise(readPsbt(v.signedBoth))).toBe(v.final);
  });

  test("every signature from both wallets passes the app's own check", () => {
    expect(stripInvalid(readPsbt(v.signedBoth)).dropped).toBe(0);
  });

  test("the summary: both signers, Core's change seen as change, nothing to warn about", () => {
    const s = summarise(readPsbt(v.signedBoth), wallet, "regtest");
    expect(s.txid).toBe(v.txid);
    expect(s.complete).toBe(true);
    expect(s.warnings).toEqual([]);
    expect(s.signers.sort()).toEqual([v.fingerprints.core, v.fingerprints.drongo].sort());
    expect(s.inputs.every((i) => i.mine)).toBe(true);
    expect(s.outputs.map((o) => o.kind).sort()).toEqual(["change", "external"]);
    expect(s.outputs.find((o) => o.kind === "external")!.address).toBe(v.payee);
  });

  test("one signature is one short, and cannot be finalised", () => {
    for (const one of [v.signedCore, v.signedDrongo]) {
      const s = summarise(readPsbt(one), wallet, "regtest");
      expect(s.missing).toBe(1);
      expect(() => finalise(readPsbt(one))).toThrow(/cannot finalise/);
    }
  });
});

describe("a Trezor (emulator, through HWI) as the second signer", () => {
  const read = readPsbt;
  test("its signatures pass the app's own check", () => {
    expect(stripInvalid(read(v.signedTrezor)).dropped).toBe(0);
    expect(summarise(read(v.signedTrezor), wallet, "regtest").signers).toEqual([v.fingerprints.trezor]);
  });

  test.each([
    ["Core", () => v.signedCore, () => v.finalCoreTrezor],
    ["drongo", () => v.signedDrongo, () => v.finalDrongoTrezor],
  ])("%s + Trezor, either order: the transaction Core made", (_, other, final) => {
    expect(finalise(combine(read(other()), read(v.signedTrezor)))).toBe(final());
    expect(finalise(combine(read(v.signedTrezor), read(other())))).toBe(final());
  });

  test("all three merged: three signers shown, and Core's choice of two", () => {
    const all = combine(combine(read(v.signedCore), read(v.signedTrezor)), read(v.signedDrongo));
    const s = summarise(all, wallet, "regtest");
    expect(s.signers.sort()).toEqual(Object.values(v.fingerprints).sort());
    expect(s.warnings).toEqual([]);
    expect(finalise(all)).toBe(v.finalAll);
  });
});
