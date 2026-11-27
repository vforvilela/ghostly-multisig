/**
 * src/miniscript.ts on its own: for the shapes Liana's compiler writes (liana/src/descriptors/mod.rs), every signer set
 * and timelock state gives a witness exactly when the policy says it is spendable, and that witness runs.
 */
import { describe, expect, test } from "vitest";
import { compile, missingSignatures, olderMet, parseMiniscript, printMiniscript, runWitness, satisfaction } from "../../src/miniscript.ts";

const POLICIES = [
  "or_d(pk(A),and_v(v:pkh(B),older(10)))",
  "or_d(multi(2,A,B),and_v(v:thresh(2,pkh(A2),a:pkh(C)),older(10)))",
  "or_i(and_v(v:thresh(2,pkh(A4),a:pkh(B4),a:pkh(C4)),older(20)),or_d(multi(2,A,B),and_v(v:thresh(2,pkh(A2),a:pkh(C)),older(10))))",
  "or_d(pk(A),and_v(v:multi(2,B,C,D),older(65535)))",
  "andor(pk(A),older(5),or_i(and_v(v:pkh(B),older(10)),and_v(v:pkh(C),after(800000))))",
  "or_b(pk(A),s:pk(B))",
  "thresh(2,pk(A),s:pk(B),sln:older(10))",
];

function keysOf(text: string) {
  const names: string[] = [];
  const ms = parseMiniscript(text, (k) => (names.includes(k) ? names.indexOf(k) : names.push(k) - 1));
  // Distinct fake keys and signatures: a key's "signature" is 0x30 then its index, then SIGHASH_ALL.
  const pubkeys = names.map((_, i) => Uint8Array.of(2, ...new Uint8Array(31), i));
  const sig = (i: number) => Uint8Array.of(0x30, i, ...new Uint8Array(68), 1);
  return { ms, names, pubkeys, sig };
}

describe("miniscript", () => {
  test.each(POLICIES)("%s: printed, reads back the same", (text) => {
    const { ms, names } = keysOf(text);
    const printed = printMiniscript(ms, (i) => names[i]);
    expect(printMiniscript(keysOf(printed).ms, (i) => keysOf(printed).names[i])).toBe(printed);
    expect(keysOf(printed).ms).toEqual(ms);
  });

  test.each(POLICIES)("%s: a witness exactly when the policy is met, and it runs", (text) => {
    const { ms, names, pubkeys, sig } = keysOf(text);
    const script = compile(ms, pubkeys);
    for (let mask = 0; mask < 1 << names.length; mask++) {
      for (const locks of [false, true]) {
        const signed = (i: number) => !!(mask & (1 << i));
        const time = { older: () => locks, after: () => locks };
        const items = satisfaction(ms, { pubkey: (i) => pubkeys[i], sig: (i) => (signed(i) ? sig(i) : undefined), ...time });
        expect(items !== null, `signers ${mask.toString(2)}, timelocks ${locks}`).toBe(missingSignatures(ms, signed, time) === 0);
        if (!items) continue;
        const ran = runWitness(items, script, {
          checkSig: (pk, s) => pubkeys.findIndex((p) => p.every((x, j) => x === pk[j])) === s[1] && s[0] === 0x30,
          ...time,
        });
        expect(ran, `signers ${mask.toString(2)}, timelocks ${locks}`).not.toBeNull();
        for (const { pubkey } of ran!) expect(signed(pubkey[32])).toBe(true);
      }
    }
  });

  test("BIP 68: older(n) against a transaction's nSequence and version", () => {
    expect(olderMet(10, 10, 2)).toBe(true);
    expect(olderMet(10, 9, 2)).toBe(false);
    expect(olderMet(10, 10, 1)).toBe(false);
    expect(olderMet(10, 0xfffffffd, 2)).toBe(false);
    expect(olderMet(10, 0x00400000 | 10, 2)).toBe(false);
  });

  test("the script of Liana's simplest wallet, opcode for opcode", () => {
    const { ms, pubkeys } = keysOf("or_d(pk(A),and_v(v:pkh(B),older(52560)))");
    const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
    const s = hexOf(compile(ms, pubkeys));
    // <A> CHECKSIG IFDUP NOTIF DUP HASH160 <hash B> EQUALVERIFY CHECKSIGVERIFY <52560> CSV ENDIF
    expect(s.startsWith(`21${hexOf(pubkeys[0])}ac736476a914`)).toBe(true);
    expect(s.endsWith("88ad0350cd00b268")).toBe(true);
  });
});
