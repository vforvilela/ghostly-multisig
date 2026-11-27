/**
 * test/vectors/coldcard.json (made by scripts/interop/coldcard.mjs): the app's multisig setup file as read by
 * Coldcard's simulator, Sparrow, Passport and Keystone. The nested format is spelled "P2WSH-P2SH" (the alias-* files):
 * Sparrow refuses "P2SH-P2WSH", and Keystone only derives addresses for "P2WSH-P2SH".
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { caravanWallet, coldcardFile, parseWallet } from "../../src/descriptor.ts";

const read = (name: string) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));
type Result = { accepted: boolean; error?: string; threshold?: number; script?: string; keys?: unknown[] };
type Case = { network: string; file: string; expected: { threshold: number; script: string; keys: unknown[] }; parsers: Record<string, Result | { chain: string; enrol: Result; parse: Result }> };
const cases = read("coldcard.json").cases as Record<string, Case>;

function descriptorOf(name: string): string {
  if (name === "signing") return read("signing.json").descriptor;
  if (name.startsWith("hardware-")) return read("hardware.json").devices[name.slice(9)].descriptor;
  return caravanWallet(readFileSync(new URL(`../vectors/caravan/${name.slice(8)}.json`, import.meta.url), "utf8"))!.descriptor;
}

describe.each(Object.keys(cases).filter((n) => !n.startsWith("alias-")))("%s", (name) => {
  const text = coldcardFile(parseWallet(descriptorOf(name)));
  const c = cases[text.includes("Format: P2WSH-P2SH") ? `alias-${name}` : name];

  test("the app writes the very file the parsers read", () => expect(text).toBe(c.file));

  test("Coldcard, Sparrow and Passport read it on its own chain, as the same wallet", () => {
    const test = c.network !== "main";
    const want = [test ? "sparrow-testnet" : "sparrow-mainnet", test ? "passport-XTN" : "passport-BTC"];
    const cc = Object.entries(c.parsers).filter(([p]) => p.startsWith("cc-") && (c.parsers[p] as { chain: string }).chain === (test ? "XTN" : "BTC"));
    expect(cc.length).toBeGreaterThan(0);
    const got: Result[] = [...want.map((p) => c.parsers[p] as Result), ...cc.map(([, r]) => (r as { parse: Result }).parse)];
    for (const r of got) {
      expect(r.error).toBeUndefined();
      expect({ threshold: r.threshold, script: r.script, keys: r.keys }).toEqual({ threshold: c.expected.threshold, script: c.expected.script, keys: c.expected.keys });
    }
  });

  test("Keystone reads a mainnet file; a testnet one is its own firmware's limit", () => {
    const k = c.parsers.keystone as Result;
    if (c.network === "main") expect(k.accepted).toBe(true);
    else expect(k.error).toMatch(/don't support testnet/);
  });
});
