/**
 * test/vectors/liana.json (made by scripts/interop/liana.mjs): a Liana wallet (three spending paths: 2 of A, B now;
 * 2 of A, C after 10 blocks; 2 of A, B, C after 20) run by lianad 16.0 on regtest, each co-signer a Bitcoin Core
 * wallet. lianad created both spends, merged the co-signers' copies, finalised and broadcast them, and Core mined
 * them. Here the app must read the wallet as Liana does, name who signed, merge the copies in either order, finalise
 * each to the very transaction lianad broadcast, and warn on the recovery spend.
 */
import { readFileSync } from "node:fs";
import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vitest";
import { DescriptorError, deriveScript, fingerprints, parseWallet } from "../../src/descriptor.ts";
import { addressOf, combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";
import { spendPaths } from "../../src/miniscript.ts";
import { walletPaths } from "../../src/ui.ts";
import { en } from "../../src/strings.ts";

const v = JSON.parse(readFileSync(new URL("../vectors/liana.json", import.meta.url), "utf8"));
const wallet = parseWallet(v.descriptor);
const { A, B, C } = v.keys as Record<"A" | "B" | "C", string>;
const witnesses = (raw: string) => {
  const tx = Transaction.fromRaw(hex.decode(raw), { allowUnknownOutputs: true });
  return Array.from({ length: tx.inputsLength }, (_, i) => tx.getInput(i).finalScriptWitness!.map((w) => hex.encode(w)));
};

describe("Liana's wallet", () => {
  test("the receive addresses lianad handed out (it starts at index 1)", () => {
    expect(v.receive.map((_: string, i: number) => addressOf(deriveScript(wallet, wallet.branches.receive, i + 1).script, "regtest"))).toEqual(v.receive);
  });

  test("its spending paths and co-signers", () => {
    expect(fingerprints(wallet)).toEqual([A, B, C]);
    expect(spendPaths(wallet.policy!).map((p) => [p.groups.map((g) => [g.k, g.keys.map((k) => wallet.keys[k].fingerprint)]), p.older])).toEqual([
      [[[2, [A, B, C]]], [20]],
      [[[2, [A, B]]], []],
      [[[2, [A, C]]], [10]],
    ]);
    expect(walletPaths(wallet, en)).toBe(`after 20 blocks, 2 of ${A}, ${B}, ${C} · 2 of ${A}, ${B} · after 10 blocks, 2 of ${A}, ${C}`);
  });

  test("the same wallet whatever the checksum", () => {
    expect(parseWallet(v.descriptor.split("#")[0]).id).toBe(wallet.id);
  });
});

describe("Liana's primary spend (2 of A, B)", () => {
  const p = v.primary;

  test("read against the wallet: lianad's change is change, nothing is signed yet", () => {
    const sum = summarise(readPsbt(p.unsigned), wallet, "regtest");
    expect(sum.txid).toBe(p.txid);
    expect(sum.inputs.every((i) => i.mine)).toBe(true);
    expect(sum.outputs.map((o) => o.kind).sort()).toEqual(["change", "external"]);
    expect(sum.warnings).toEqual([]);
    expect(sum.missing).toBe(2);
    expect(sum.complete).toBe(false);
  });

  test("each co-signer's copy names that co-signer, and one is still missing", () => {
    for (const [copy, who] of [[p.signedA, A], [p.signedB, B]]) {
      expect(stripInvalid(readPsbt(copy)).dropped).toBe(0);
      const sum = summarise(readPsbt(copy), wallet, "regtest");
      expect(sum.signers).toEqual([who]);
      expect(sum.missing).toBe(1);
      expect(sum.complete).toBe(false);
      expect(() => finalise(readPsbt(copy), wallet)).toThrow(/cannot finalise yet/);
    }
  });

  test("merged in either order: complete, and finalised to the transaction lianad broadcast", () => {
    for (const [a, b] of [[p.signedA, p.signedB], [p.signedB, p.signedA]]) {
      const merged = combine(readPsbt(a), readPsbt(b));
      const sum = summarise(merged, wallet, "regtest");
      expect(sum.signers).toEqual([A, B]);
      expect(sum.missing).toBe(0);
      expect(sum.complete).toBe(true);
      expect(sum.warnings).toEqual([]);
      expect(finalise(merged, wallet)).toBe(p.final);
    }
    expect(finalise(readPsbt(p.mergedByLiana), wallet)).toBe(p.final);
  });

  test("the witness is the primary path's: multi's dummy and two signatures, then or_i's second branch", () => {
    const [w] = witnesses(p.final);
    expect(w.map((x) => x.length / 2)).toEqual([0, w[1].length / 2, w[2].length / 2, 0, w[4].length / 2]);
  });

  test("the vsize estimate before signing is close to the real one", () => {
    const tx = Transaction.fromRaw(hex.decode(p.final), { allowUnknownOutputs: true });
    const est = summarise(readPsbt(p.unsigned), wallet, "regtest").vsize;
    expect(est).toBeGreaterThanOrEqual(tx.vsize);
    expect(est - tx.vsize).toBeLessThanOrEqual(2);
  });
});

describe("Liana's recovery spend (after 10 blocks, 2 of A, C)", () => {
  const r = v.recovery;

  test("warned as a recovery spend, with its timelock", () => {
    const sum = summarise(readPsbt(r.unsigned), wallet, "regtest");
    expect(sum.txid).toBe(r.txid);
    expect(sum.inputs.length).toBe(2);
    expect(sum.inputs.every((i) => i.mine)).toBe(true);
    expect(sum.warnings).toEqual([{ k: "recovery-path", blocks: 10 }]);
    expect(sum.missing).toBe(2);
  });

  test("A's copy holds its signatures on every path, and one more (C's) is still needed", () => {
    const sum = summarise(readPsbt(r.signedA), wallet, "regtest");
    expect(sum.signers).toEqual([A]);
    expect(sum.missing).toBe(1);
    expect(summarise(readPsbt(r.signedC), wallet, "regtest").signers).toEqual([C]);
  });

  test("merged in either order: finalised to the transaction lianad broadcast", () => {
    for (const [a, b] of [[r.signedA, r.signedC], [r.signedC, r.signedA]]) {
      const merged = combine(readPsbt(a), readPsbt(b));
      const sum = summarise(merged, wallet, "regtest");
      expect(sum.signers).toEqual([A, C]);
      expect(sum.complete).toBe(true);
      expect(sum.warnings).toEqual([{ k: "recovery-path", blocks: 10 }]);
      expect(finalise(merged, wallet)).toBe(r.final);
    }
    expect(finalise(readPsbt(r.mergedByLiana), wallet)).toBe(r.final);
  });

  test("lianad's broadcast transaction, read back as finalised inputs, checks out", () => {
    const tx = readPsbt(r.unsigned);
    const done = Transaction.fromRaw(hex.decode(r.final), { allowUnknownOutputs: true });
    for (let n = 0; n < tx.inputsLength; n++) tx.updateInput(n, { finalScriptWitness: done.getInput(n).finalScriptWitness }, true);
    const sum = summarise(tx, wallet, "regtest");
    expect(sum.inputs.every((i) => i.final)).toBe(true);
    expect(sum.signers).toEqual([A, C]);
    expect(sum.complete).toBe(true);
    expect(stripInvalid(tx).dropped).toBe(0);
    // A witness cut short does not spend: stripInvalid takes it back to unsigned.
    const cut = readPsbt(r.unsigned);
    cut.updateInput(0, { finalScriptWitness: done.getInput(0).finalScriptWitness!.slice(2) }, true);
    expect(stripInvalid(cut).dropped).toBe(1);
  });

  test("the witness is the 10-block path's: C's and A's signatures and keys, the rest dissatisfied", () => {
    for (const w of witnesses(r.final)) {
      expect(w.length).toBe(9);
      expect([w[1].length, w[3].length]).toEqual([66, 66]);
      expect(w.slice(4, 8)).toEqual(["", "", "", ""]);
    }
  });

  test("only one co-signer is not enough, whatever the timelock", () => {
    expect(() => finalise(readPsbt(r.signedA), wallet)).toThrow(/cannot finalise yet/);
  });
});

describe("Liana descriptors", () => {
  const tpub = (n: number) => wallet.keys[n].xpub;
  const key = (fp: string, origin: string, xpub: string, pair: string) => `[${fp}/${origin}]${xpub}/<${pair}>/*`;
  const o = "48h/1h/0h/2h";

  test("Liana's simplest shape: one primary key, one recovery key after N blocks", () => {
    const w = parseWallet(`wsh(or_d(pk(${key(A, o, tpub(1), "0;1")}),and_v(v:pkh(${key(B, o, tpub(2), "0;1")}),older(52560))))`);
    expect(w.policy).toBeDefined();
    expect(walletPaths(w, en)).toBe(`1 of ${A} · after 52560 blocks, 1 of ${B}`);
    expect(deriveScript(w, w.branches.change, 0).witnessScript.length).toBeGreaterThan(0);
  });

  test("one key reused on several paths, a multi primary, and thresh recovery", () => {
    const w = parseWallet(
      `wsh(or_d(multi(2,${key(A, o, tpub(1), "0;1")},${key(B, o, tpub(3), "0;1")}),and_v(v:thresh(1,pkh(${key(A, o, tpub(1), "2;3")}),a:pkh(${key(C, o, tpub(6), "0;1")})),older(100))))`,
    );
    expect(fingerprints(w)).toEqual([A, B, C]);
    expect(w.keys.length).toBe(4);
  });

  test("the same key at the same path twice is refused", () => {
    expect(() => parseWallet(`wsh(or_d(pk(${key(A, o, tpub(1), "0;1")}),and_v(v:pkh(${key(A, o, tpub(1), "0;1")}),older(10))))`)).toThrow(
      /the same key is in the wallet twice/,
    );
  });

  test("Taproot Liana wallets are refused, plainly", () => {
    expect(() => parseWallet(`tr(${key(A, o, tpub(1), "0;1")},and_v(v:pk(${key(B, o, tpub(2), "0;1")}),older(10)))`)).toThrow(
      /^Taproot Liana wallets are not supported yet$/,
    );
  });

  test("keys without a <receive;change> step, time-based timelocks and hash locks are refused", () => {
    expect(() => parseWallet(`wsh(or_d(pk([${A}/${o}]${tpub(1)}/0/*),and_v(v:pkh(${key(B, o, tpub(2), "0;1")}),older(10))))`)).toThrow(DescriptorError);
    expect(() => parseWallet(`wsh(or_d(pk(${key(A, o, tpub(1), "0;1")}),and_v(v:pkh(${key(B, o, tpub(2), "0;1")}),older(4194305))))`)).toThrow(
      /timelocks in blocks/,
    );
    expect(() => parseWallet(`wsh(and_v(v:pk(${key(A, o, tpub(1), "0;1")}),sha256(${"00".repeat(32)})))`)).toThrow(/hash locks/);
  });

  test("a miniscript that is not a valid script is refused", () => {
    // or_d's first argument must be dissatisfiable and unit: older() is neither.
    expect(() => parseWallet(`wsh(or_d(older(10),pk(${key(A, o, tpub(1), "0;1")})))`)).toThrow(/not of the types/);
    expect(() => parseWallet(`wsh(v:pk(${key(A, o, tpub(1), "0;1")}))`)).toThrow(/not a complete script/);
  });
});
