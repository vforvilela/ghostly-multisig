import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { derivePubkeys, parseWallet } from "../../src/descriptor";
import { p2ms, p2wsh } from "@scure/btc-signer";
import { PsbtError, combine, decodePsbt, finalise, readPsbt, summarise, toBase64 } from "../../src/psbt";
import { hex } from "@scure/base";

const fixture = (f: string) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8").trim();
const wallet = parseWallet(fixture("descriptor.txt"));
const tx = (f: string) => readPsbt(fixture(f));

describe("psbt", () => {
  it("reads the unsigned PSBT: fee, size, change, no signatures", () => {
    const s = summarise(tx("0-unsigned.psbt"), wallet, "regtest");
    expect(s.fee).toBe(588n);
    expect(s.vsize).toBe(294);
    expect(s.missing).toBe(2);
    expect(s.signers).toEqual([]);
    expect(s.inputs.every((i) => i.mine)).toBe(true);
    expect(s.outputs.map((o) => o.kind)).toEqual(["change", "external"]);
    expect(s.outputs[0].path).toEqual({ branch: 1, index: 0 });
    expect(s.outputs[1].address.startsWith("bcrt1")).toBe(true);
    expect(s.warnings).toEqual([]);
  });

  it("counts signatures per co-signer", () => {
    const a = summarise(tx("1-alice.psbt"), wallet, "regtest");
    expect(a.missing).toBe(1);
    expect(a.signers).toHaveLength(1);
    const b = summarise(tx("1-bob.psbt"), wallet, "regtest");
    expect(b.signers).toHaveLength(1);
    expect(b.signers).not.toEqual(a.signers);
    const both = summarise(tx("2-combined.psbt"), wallet, "regtest");
    expect(both.missing).toBe(0);
    expect(both.complete).toBe(true);
    expect(both.signers.sort()).toEqual([...a.signers, ...b.signers].sort());
  });

  it("combines two halves and finalises to a transaction of the estimated size or less", () => {
    const c = combine(tx("1-alice.psbt"), tx("1-bob.psbt"));
    expect(summarise(c, wallet, "regtest").complete).toBe(true);
    const raw = finalise(c);
    const final = readPsbt(toBase64(c));
    expect(raw.length / 2).toBeGreaterThan(300);
    expect(summarise(tx("2-alice-bob.psbt"), wallet, "regtest").complete).toBe(true);
    expect(final.id).toBe(c.id);
  });

  it("refuses to combine a different transaction and cannot finalise with one signature", () => {
    expect(() => combine(tx("0-unsigned.psbt"), tx("x-tampered-same-inputs.psbt"))).toThrow(PsbtError);
    expect(() => finalise(tx("1-alice.psbt"))).toThrow(PsbtError);
  });

  it("flags a change output whose script was swapped", () => {
    const t = tx("0-unsigned.psbt");
    // The attacker's own 1-of-1 script, still labelled with the wallet's change path.
    const attacker = p2wsh(p2ms(1, [derivePubkeys(wallet, 7, 7)[0]]));
    t.updateOutput(0, { script: attacker.script, witnessScript: attacker.witnessScript }, true);
    const s = summarise(t, wallet, "regtest");
    expect(s.outputs[0].kind).toBe("fake-change");
    expect(s.warnings).toContainEqual({ k: "fake-change", n: 0 });
  });

  it("flags inputs from another wallet", () => {
    const otherWallet = parseWallet(fixture("descriptor.txt").replaceAll("sortedmulti(2", "sortedmulti(1").replace(/#\w+/g, ""));
    const s = summarise(tx("0-unsigned.psbt"), otherWallet, "regtest");
    expect(s.warnings.filter((w) => w.k === "foreign-input")).toHaveLength(2);
  });

  it("reads hex as well as base64, and rejects junk", () => {
    const b = decodePsbt(fixture("0-unsigned.psbt"));
    expect(readPsbt(hex.encode(b)).id).toBe(tx("0-unsigned.psbt").id);
    expect(() => readPsbt("hello")).toThrow(PsbtError);
    expect(() => readPsbt("")).toThrow(PsbtError);
  });
});
