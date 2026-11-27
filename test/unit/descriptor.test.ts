import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { DescriptorError, deriveScript, descriptorChecksum, parseWallet } from "../../src/descriptor";

const fixture = (f: string) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8");
const lines = fixture("descriptor.txt").split("\n").filter((l) => l.startsWith("wsh"));

describe("descriptor", () => {
  it("checksums like Bitcoin Core", () => {
    for (const l of lines) {
      const [body, sum] = l.split("#");
      expect(descriptorChecksum(body)).toBe(sum);
    }
  });

  it("reads the receive and change lines as one 2-of-3 wallet", () => {
    const w = parseWallet(lines.join("\n"));
    expect(w.threshold).toBe(2);
    expect(w.keys.map((k) => k.fingerprint)).toEqual(["4525ed37", "e5ae5b12", "311bb6ba"]);
    expect(w.branches).toEqual({ receive: 0, change: 1 });
    expect(w.chain).toBe("test");
    expect(w.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it("gives the same id for <0;1> and for the two lines, in any key order", () => {
    const two = parseWallet(lines.join("\n"));
    const body = lines[0].split("#")[0].replaceAll("/0/*", "/<0;1>/*");
    const one = parseWallet(body);
    expect(one.id).toBe(two.id);
    const m = /^wsh\(sortedmulti\(2,(.*)\)\)$/.exec(body)!;
    const k = m[1].split(",");
    expect(parseWallet(`wsh(sortedmulti(2,${[k[2], k[0], k[1]].join(",")}))`).id).toBe(two.id);
    expect(parseWallet(`wsh(multi(2,${k.join(",")}))`).id).not.toBe(two.id);
  });

  it("derives the change script in the fixture PSBT", () => {
    const w = parseWallet(lines.join("\n"));
    const { script } = deriveScript(w, 1, 0);
    expect(script.length).toBe(34);
  });

  it("refuses a changed checksum, missing origins, a single line without change, and private keys", () => {
    const bad = lines[0].slice(0, -1) + (lines[0].endsWith("a") ? "b" : "a");
    expect(() => parseWallet(bad)).toThrow(/checksum/);
    expect(() => parseWallet(lines[0])).toThrow(/change/);
    const noOrigin = lines[0].split("#")[0].replace(/\[[^\]]+\]/, "");
    expect(() => parseWallet(noOrigin)).toThrow(DescriptorError);
    expect(() => parseWallet("wsh(sortedmulti(2,[00000000/84h/1h/0h]tprv8ZgxMBicQKsPd/0/*))")).toThrow(DescriptorError);
    expect(() => parseWallet("pkh(foo)")).toThrow(/wsh/);
  });
});
