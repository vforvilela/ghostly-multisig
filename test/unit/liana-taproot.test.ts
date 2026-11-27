/**
 * test/vectors/liana-taproot.json (made by scripts/interop/liana-taproot.mjs): two Taproot Liana wallets run by
 * lianad 16.0 on regtest, each co-signer a Bitcoin Core wallet. lianad handed out the addresses, created both spends
 * of each wallet, merged the co-signers' copies, finalised and broadcast them; Core mined them.
 *
 *   nums:    unspendable internal key (Liana's NUMS xpub); leaves 2 of A, B | after 10, 2 of A, C | after 20, 2 of A, B, C
 *   keypath: A is the internal key (a key-path spend); one leaf, after 10, B
 *
 * The app must read each wallet as lianad does (the same addresses), name who signed, merge the copies in either
 * order, finalise each to the very transaction lianad broadcast, estimate its size, and warn on the recovery spends.
 */
import { readFileSync } from "node:fs";
import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vitest";
import { DescriptorError, NUMS_H, deriveScript, deriveTaproot, fingerprints, parseWallet, walletSpendPaths } from "../../src/descriptor.ts";
import { addressOf, combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";
import { walletPaths } from "../../src/ui.ts";
import { en } from "../../src/strings.ts";

const v = JSON.parse(readFileSync(new URL("../vectors/liana-taproot.json", import.meta.url), "utf8"));
const { A, B, C } = v.keys as Record<"A" | "B" | "C", string>;
const nums = parseWallet(v.nums.descriptor);
const keypath = parseWallet(v.keypath.descriptor);
const raw = (t: string) => Transaction.fromRaw(hex.decode(t), { allowUnknownOutputs: true });
const witnesses = (t: string) => {
  const tx = raw(t);
  return Array.from({ length: tx.inputsLength }, (_, i) => tx.getInput(i).finalScriptWitness!.map((w) => hex.encode(w)));
};

describe.each([
  ["nums", nums],
  ["keypath", keypath],
] as const)("Liana's Taproot wallet (%s)", (name, wallet) => {
  const x = v[name];

  test("the receive and change addresses lianad lists, and those it handed out", () => {
    for (const a of x.addresses) {
      expect(addressOf(deriveScript(wallet, wallet.branches.receive, a.index).script, "regtest")).toBe(a.receive);
      expect(addressOf(deriveScript(wallet, wallet.branches.change, a.index).script, "regtest")).toBe(a.change);
    }
    expect(x.receive.map((_: string, i: number) => addressOf(deriveScript(wallet, wallet.branches.receive, i + 1).script, "regtest"))).toEqual(x.receive);
  });

  test("the same wallet whatever the checksum", () => {
    expect(parseWallet(x.descriptor.split("#")[0]).id).toBe(wallet.id);
    expect(wallet.id).not.toBe(name === "nums" ? keypath.id : nums.id);
  });
});

describe("the wallets' paths and co-signers", () => {
  test("nums: three leaves; the unspendable key is no co-signer", () => {
    expect(nums.taproot!.internal).toBeNull();
    expect(fingerprints(nums)).toEqual([A, B, C]);
    expect(walletSpendPaths(nums).map((p) => p.older)).toEqual([[], [10], [20]]);
    expect(walletPaths(nums, en)).toBe(`2 of ${A}, ${B} · after 10 blocks, 2 of ${A}, ${C} · after 20 blocks, 2 of ${A}, ${B}, ${C}`);
  });

  test("keypath: the key path first, then the leaf", () => {
    expect(keypath.taproot!.internal).toBe(0);
    expect(fingerprints(keypath)).toEqual([A, B]);
    expect(walletPaths(keypath, en)).toBe(`1 of ${A} · after 10 blocks, 1 of ${B}`);
  });
});

describe.each([
  ["nums", "primary", ["A", "B"], 2],
  ["keypath", "primary", ["A"], 1],
  ["nums", "recovery", ["A", "C"], 2],
  ["keypath", "recovery", ["B"], 1],
] as const)("Liana's %s wallet, its %s spend", (name, spend, who, k) => {
  const wallet = { nums, keypath }[name];
  const p = v[name][spend];
  const fps = who.map((w) => v.keys[w]);
  const recovery = spend === "recovery" ? [{ k: "recovery-path", blocks: 10 }] : [];

  test("read against the wallet: nothing signed yet, change is change, a recovery spend warns", () => {
    const sum = summarise(readPsbt(p.unsigned), wallet, "regtest");
    expect(sum.txid).toBe(p.txid);
    expect(sum.inputs.length).toBe(spend === "primary" ? 1 : 2);
    expect(sum.inputs.every((i) => i.mine)).toBe(true);
    expect(sum.outputs.map((o) => o.kind).sort()).toEqual(spend === "primary" ? ["change", "external"] : ["external"]);
    expect(sum.warnings).toEqual(recovery);
    expect(sum.missing).toBe(k);
    expect(sum.signers).toEqual([]);
  });

  test("each co-signer's copy names that co-signer", () => {
    for (const [i, w] of who.entries()) {
      const copy = readPsbt(p.signed[w]);
      expect(stripInvalid(copy).dropped).toBe(0);
      const sum = summarise(copy, wallet, "regtest");
      expect(sum.signers).toEqual([fps[i]]);
      expect(sum.missing).toBe(k - 1);
      expect(sum.warnings).toEqual(recovery);
      if (k > 1) expect(() => finalise(copy, wallet)).toThrow(/cannot finalise yet/);
    }
  });

  test("merged in either order: complete, and finalised to the transaction lianad broadcast", () => {
    const copies = who.map((w) => p.signed[w]);
    for (const order of copies.length === 2 ? [copies, [...copies].reverse()] : [copies]) {
      const merged = order.slice(1).reduce((acc, c) => combine(acc, readPsbt(c)), readPsbt(order[0]));
      const sum = summarise(merged, wallet, "regtest");
      expect(sum.signers).toEqual(fps);
      expect(sum.missing).toBe(0);
      expect(sum.complete).toBe(true);
      expect(sum.warnings).toEqual(recovery);
      expect(finalise(merged, wallet)).toBe(p.final);
    }
    expect(summarise(readPsbt(p.mergedByLiana), wallet, "regtest").signers).toEqual(fps);
    expect(finalise(readPsbt(p.mergedByLiana), wallet)).toBe(p.final);
  });

  test("the vsize estimate before signing is within 2 vbytes over the real one", () => {
    const est = summarise(readPsbt(p.unsigned), wallet, "regtest").vsize;
    expect(est).toBeGreaterThanOrEqual(raw(p.final).vsize);
    expect(est - raw(p.final).vsize).toBeLessThanOrEqual(2);
  });

  test("lianad's broadcast transaction, read back as finalised inputs, checks out; a cut witness does not", () => {
    const tx = readPsbt(p.unsigned);
    const done = raw(p.final);
    for (let n = 0; n < tx.inputsLength; n++) tx.updateInput(n, { finalScriptWitness: done.getInput(n).finalScriptWitness }, true);
    const sum = summarise(tx, wallet, "regtest");
    expect(sum.inputs.every((i) => i.final)).toBe(true);
    expect(sum.signers).toEqual(fps);
    expect(sum.complete).toBe(true);
    expect(stripInvalid(tx).dropped).toBe(0);
    const cut = readPsbt(p.unsigned);
    const w = done.getInput(0).finalScriptWitness!;
    cut.updateInput(0, { finalScriptWitness: w.length > 1 ? w.slice(1) : [w[0].subarray(1)] }, true);
    expect(stripInvalid(cut).dropped).toBe(1);
  });
});

describe("the witnesses lianad broadcast, and the app made", () => {
  test("keypath primary: a key-path spend, one 64-byte signature", () => {
    expect(witnesses(v.keypath.primary.final)).toEqual([[expect.stringMatching(/^[0-9a-f]{128}$/)]]);
  });

  test("nums primary: the 2-of-A,B leaf, B's signature under A's, then the leaf and its control block", () => {
    const [w] = witnesses(v.nums.primary.final);
    const addr = deriveTaproot(nums, 0, 1);
    expect(w.map((i) => i.length / 2)).toEqual([64, 64, addr.leaves[0].script.length, 33 + 32]);
  });

  test("nums recovery: the 10-block leaf, at depth 2", () => {
    for (const w of witnesses(v.nums.recovery.final)) expect(w.map((i) => i.length / 2).slice(0, 2).concat(w[3].length / 2)).toEqual([64, 64, 33 + 64]);
  });
});

describe("signatures that do not belong", () => {
  test("a signature moved to another leaf is dropped", () => {
    const copy = readPsbt(v.nums.primary.signed.A);
    const sigs = copy.getInput(0).tapScriptSig!;
    // A signs in all three leaves, each at its own path: each signature goes to the next one's leaf.
    copy.updateInput(0, { tapScriptSig: undefined }, true);
    copy.updateInput(0, { tapScriptSig: sigs.map(([k, s], i) => [{ pubKey: k.pubKey, leafHash: sigs[(i + 1) % sigs.length][0].leafHash }, s]) }, true);
    expect(stripInvalid(copy).dropped).toBe(sigs.length);
    expect(summarise(copy, nums, "regtest").signers).toEqual([]);
  });

  test("a key-path signature that does not verify is dropped, and a merge does not let it in", () => {
    const forged = readPsbt(v.keypath.primary.signed.A);
    const sig = forged.getInput(0).tapKeySig!.slice();
    sig[10] ^= 1;
    forged.updateInput(0, { tapKeySig: sig }, true);
    expect(stripInvalid(forged).dropped).toBe(1);
    expect(summarise(forged, keypath, "regtest").signers).toEqual([]);
    const merged = combine(readPsbt(v.keypath.primary.unsigned), forged);
    expect(merged.getInput(0).tapKeySig).toBeUndefined();
    expect(() => finalise(merged, keypath)).toThrow(/cannot finalise yet/);
  });
});

describe("Taproot Liana descriptors", () => {
  const key = (n: number, pair: string) => {
    const k = nums.keys[n];
    return `[${k.fingerprint}/48h/1h/0h/2h]${k.xpub}/<${pair}>/*`;
  };
  const numsXpub = (v.nums.descriptor as string).slice(3).split("/")[0];

  test("the unspendable key with an origin, or as BIP 341's H itself", () => {
    const tree = `{multi_a(2,${key(0, "0;1")},${key(1, "0;1")}),and_v(v:pk(${key(3, "0;1")}),older(10))}`;
    const plain = parseWallet(`tr(${numsXpub}/<0;1>/*,${tree})`);
    expect(parseWallet(`tr([00000000]${numsXpub}/<0;1>/*,${tree})`).id).toBe(plain.id);
    const h = parseWallet(`tr(${hex.encode(NUMS_H)},${tree})`);
    expect(h.taproot!.internal).toBeNull();
    expect(deriveTaproot(h, 0, 0).internal).toEqual(NUMS_H);
    expect(fingerprints(h)).toEqual([A, B, C]);
  });

  test("Liana's one-key primary with a long recovery, as it writes it", () => {
    const w = parseWallet(`tr(${key(0, "0;1")},and_v(v:pk(${key(1, "0;1")}),older(52560)))`);
    expect(walletPaths(w, en)).toBe(`1 of ${A} · after 52560 blocks, 1 of ${B}`);
  });

  test("refused: a co-signer's key without its origin, a bare key, multi in Tapscript, sortedmulti_a, no leaves", () => {
    const xpub = nums.keys[0].xpub;
    expect(() => parseWallet(`tr(${xpub}/<0;1>/*,pk(${key(1, "0;1")}))`)).toThrow(/needs its origin/);
    expect(() => parseWallet(`tr(${hex.encode(deriveTaproot(nums, 0, 0).xonly[0])},pk(${key(1, "0;1")}))`)).toThrow(/bare public key/);
    expect(() => parseWallet(`tr(${numsXpub}/<0;1>/*,multi(2,${key(0, "0;1")},${key(1, "0;1")}))`)).toThrow(/multi is for P2WSH/);
    expect(() => parseWallet(`tr(${numsXpub}/<0;1>/*,sortedmulti_a(2,${key(0, "0;1")},${key(1, "0;1")}))`)).toThrow(/sortedmulti_a/);
    expect(() => parseWallet(`tr(${key(0, "0;1")})`)).toThrow(/no script leaves/);
    expect(() => parseWallet(`tr(${numsXpub}/<0;1>/*,{pk(${key(0, "0;1")})})`)).toThrow(DescriptorError);
  });
});
