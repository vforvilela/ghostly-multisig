/**
 * test/vectors/caravan.json (made by scripts/interop/caravan.mjs): Caravan's own PSBT code on the spend in
 * signing.json. When the vectors were made, Caravan validated every signature in the app's merge; here the app must
 * still make that merge, refuse Caravan's v2 conversion, and finish Core's transaction from Caravan's signed copy.
 * Caravan's wallet files (its fixtures in test/vectors/caravan/, at caravan-bitcoin/caravan dff6283, MIT) must give
 * the addresses Caravan's braid code gave.
 */
import { readFileSync } from "node:fs";
import { base64 } from "@scure/base";
import { describe, expect, test } from "vitest";
import { DescriptorError, caravanWallet, deriveScript, parseWallet } from "../../src/descriptor.ts";
import { addressOf, combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";

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

describe("Caravan's wallet file", () => {
  const files: [string, string][] = Object.keys(c.wallets).map((name) => [
    name,
    name === "signing.json" ? JSON.stringify(c.wallets[name].config, null, 2) : readFileSync(new URL(`../vectors/caravan/${name}`, import.meta.url), "utf8"),
  ]);

  test.each(files)("%s: the first receive and change addresses Caravan derives", (name, text) => {
    const { network } = caravanWallet(text)!;
    const w = parseWallet(text);
    for (const [branch, side] of [[w.branches.receive, "receive"], [w.branches.change, "change"]] as const) {
      const got = c.wallets[name][side].map((_: string, i: number) => addressOf(deriveScript(w, branch, i).script, network));
      expect(got).toEqual(c.wallets[name][side]);
    }
  });

  test("signing.json's wallet as a Caravan file is the same wallet as its descriptor, on regtest", () => {
    const text = JSON.stringify(c.wallets["signing.json"].config);
    expect(parseWallet(text).id).toBe(wallet.id);
    expect(caravanWallet(text)!.network).toBe("regtest");
  });

  test("a descriptor is not taken for a Caravan file", () => {
    expect(caravanWallet(v.descriptor)).toBeNull();
  });

  test("what the app cannot read, said plainly", () => {
    const p2sh = readFileSync(new URL("../vectors/caravan/bitcoin-2-of-2-P2SH_MAINNET.json", import.meta.url), "utf8");
    expect(() => parseWallet(p2sh)).toThrow(/^Caravan P2SH wallets are not supported/);
    const config = c.wallets["signing.json"].config;
    const noOrigin = { ...config, extendedPublicKeys: config.extendedPublicKeys.map((k: object, i: number) => (i ? k : { ...k, xfp: undefined, bip32Path: "Unknown" })) };
    expect(() => parseWallet(JSON.stringify(noOrigin))).toThrow(/^key "key 1" has no fingerprint and path/);
    expect(() => parseWallet(JSON.stringify({ ...config, quorum: { requiredSigners: 2, totalSigners: 4 } }))).toThrow(/quorum does not match/);
    expect(() => parseWallet("{ not json")).toThrow(DescriptorError);
  });
});
