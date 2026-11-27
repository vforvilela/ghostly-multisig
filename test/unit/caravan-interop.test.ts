/**
 * test/vectors/caravan.json (made by scripts/interop/caravan.mjs): Caravan's own PSBT code on the spend in
 * signing.json. When the vectors were made, Caravan validated every signature in the app's merge; here the app must
 * still make that merge, refuse Caravan's v2 conversion, and finish Core's transaction from Caravan's signed copy.
 */
import { readFileSync } from "node:fs";
import { base64 } from "@scure/base";
import { describe, expect, test } from "vitest";
import { parseWallet } from "../../src/descriptor.ts";
import { combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";

const read = (name: string) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));
const v = read("signing.json");
const c = read("caravan.json");
const wallet = parseWallet(v.descriptor);

describe("Caravan", () => {
  test("the app still makes the merge Caravan validated, signature for signature", () => {
    expect(c.validated.signatures).toBe(4);
    expect(base64.encode(combine(readPsbt(v.signedCore), readPsbt(v.signedTrezor)).toPSBT(0))).toBe(c.validated.psbt);
  });

  test("Caravan's v2 conversion is refused with the version message", () => {
    expect(() => readPsbt(c.v2)).toThrow(/^PSBT version 2: export it from your wallet as version 0/);
  });

  test("Caravan's signed copy: the Trezor's signatures, valid, and Core's transaction from it", () => {
    expect(stripInvalid(readPsbt(c.caravanSigned)).dropped).toBe(0);
    expect(summarise(readPsbt(c.caravanSigned), wallet, "regtest").signers).toEqual([v.fingerprints.trezor]);
    expect(finalise(combine(readPsbt(v.signedCore), readPsbt(c.caravanSigned)))).toBe(v.finalCoreTrezor);
    expect(finalise(combine(readPsbt(c.caravanSigned), readPsbt(v.signedCore)))).toBe(v.finalCoreTrezor);
  });
});
