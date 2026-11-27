/**
 * test/vectors/ur.json (made by scripts/interop/ur.mjs): @ngraveio/bc-ur's crypto-psbt parts for signing.json's
 * PSBTs, pure and mixed. The app's encoder must make the very same parts, and its decoder read them back.
 */
import { readFileSync } from "node:fs";
import { base64 } from "@scure/base";
import { describe, expect, test } from "vitest";
import { UrError, bytewords, fromBytewords, urDecode, urEncoder } from "../../src/ur.ts";

const read = (name: string) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));
const v = read("signing.json");
const u = read("ur.json") as { fragment: number; cases: Record<string, { count: number; parts: string[] }> };

describe.each(Object.entries(u.cases))("%s as crypto-psbt", (name, c) => {
  const psbt = base64.decode(v[name]);

  test("every part, pure and mixed, the same as the reference's", () => {
    const enc = urEncoder("crypto-psbt", psbt, u.fragment);
    expect(enc.count).toBe(c.count);
    expect(c.parts.map((_, i) => enc.part(i + 1))).toEqual(c.parts);
  });

  test("read back from the pure parts, from mixed parts only, and in any order", () => {
    const pure = c.parts.slice(0, c.count);
    expect(base64.encode(urDecode(pure.join("\n")).data)).toBe(v[name]);
    expect(base64.encode(urDecode(c.parts.slice(c.count).join(" ")).data)).toBe(v[name]);
    expect(urDecode([...c.parts].reverse().join("\n").toUpperCase()).type).toBe("crypto-psbt");
  });

  test("a missing part is named, not guessed", () => {
    expect(() => urDecode(c.parts.slice(1, c.count).join("\n"))).toThrow(/^1 of \d+ QR parts missing$/);
  });
});

test("a short message is one part with no sequence, and reads back", () => {
  const data = new TextEncoder().encode("Name: x\nPolicy: 2 of 3\n");
  const enc = urEncoder("bytes", data);
  expect(enc.count).toBe(1);
  expect(enc.part(1)).toMatch(/^ur:bytes\/[a-z]+$/);
  expect(enc.part(7)).toBe(enc.part(1));
  expect(urDecode(enc.part(1))).toEqual({ type: "bytes", data });
});

test("bytewords: two letters a byte and a CRC-32; a changed letter is caught", () => {
  const data = new Uint8Array([0, 1, 2, 128, 255]);
  const words = bytewords(data);
  expect(words).toHaveLength(2 * (5 + 4));
  expect(words.slice(0, 2)).toBe("ae");
  expect(fromBytewords(words)).toEqual(data);
  expect(() => fromBytewords(`ao${words.slice(2)}`)).toThrow(/checksum/);
  expect(() => fromBytewords(`zz${words.slice(2)}`)).toThrow(UrError);
});

test("not a UR, or parts of two URs, said plainly", () => {
  expect(() => urDecode("cHNidP8B")).toThrow(/^not a UR$/);
  const a = u.cases.unsigned.parts[0];
  const b = u.cases.signedCore.parts[1];
  expect(() => urDecode(`${a}\n${b}`)).toThrow(/^parts of different URs$/);
});
