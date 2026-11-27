/**
 * Descriptors from Sparrow's tests and fixtures (test/vectors/descriptors.json, made by scripts/interop/descriptors.mjs):
 * every way of writing each wallet must give Bitcoin Core's first receive and change addresses, and the same wallet id.
 * Then descriptors other wallets write that this app must refuse.
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { Address, NETWORK, OutScript, TEST_NETWORK } from "@scure/btc-signer";
import { DescriptorError, deriveScript, parseWallet } from "../../src/descriptor.ts";

interface Case {
  name: string;
  network: "main" | "test";
  forms: Record<string, string>;
  receive: string[];
  change: string[];
}
const { cases } = JSON.parse(readFileSync(new URL("../vectors/descriptors.json", import.meta.url), "utf8")) as { cases: Case[] };
const sparrow = (file: string) => readFileSync(new URL(`../vectors/sparrow/${file}`, import.meta.url), "utf8");

const address = (script: Uint8Array, network: "main" | "test") =>
  Address(network === "main" ? NETWORK : TEST_NETWORK).encode(OutScript.decode(script));

describe.each(cases)("$name", (c) => {
  test.each(Object.entries(c.forms))("%s form gives Core's addresses", (_, text) => {
    const wallet = parseWallet(text);
    for (const [branch, expected] of [[wallet.branches.receive, c.receive], [wallet.branches.change, c.change]] as const) {
      expect(expected.map((_, i) => address(deriveScript(wallet, branch, i).script, c.network))).toEqual(expected);
    }
  });

  test("every form is the same wallet id", () => {
    expect(new Set(Object.values(c.forms).map((t) => parseWallet(t).id)).size).toBe(1);
  });
});

test("a Zpub and its xpub are the same wallet", () => {
  const plain = cases.find((c) => c.name === "Coldcard 2-of-4 P2WSH export (Sparrow fixture)")!;
  const zpub = cases.find((c) => c.name.endsWith("SLIP-132 Zpub"))!;
  expect(parseWallet(zpub.forms.multipath).id).toBe(parseWallet(plain.forms.multipath).id);
});

describe("refused, with a reason", () => {
  const refused: [string, string, RegExp][] = [
    ["Sparrow single-key export (multipath)", sparrow("descriptor-multipath.txt"), /only wsh/],
    ["Sparrow single-key export (two lines)", sparrow("descriptor-receive-change1.txt"), /only wsh/],
    ["Coldcard setup file: not a descriptor", sparrow("cc-multisig-export-1.txt"), /descriptor|only wsh/],
    [
      "BIP 383 sortedmulti without key origins",
      "wsh(sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*))",
      /origin/,
    ],
    [
      "BIP 383 private keys",
      "wsh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/<0;1>/*,[00000000/111h]xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/<0;1>/*))",
      /private/,
    ],
    [
      // drongo's MULTI_KEY_1: a depth-0 key under a 4-step origin. Core and Sparrow take it; a PSBT path could not match.
      "drongo key whose origin is longer than its depth",
      "wsh(sortedmulti(2,[04fefef0/48h/0h/0h/2h]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0;1>/*,[04ba1ef0/48h/0h/0h/2h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<0;1>/*))",
      /depth/,
    ],
    [
      "BIP 389 multipath of three",
      "wsh(multi(2,[1cf0bf7e/48h/0h/0h/2h]xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/<1;2;3>/*,[4fc1dd4a/48h/0h/0h/2h]xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj/<1;2;3>/*))",
      /cannot read/,
    ],
    [
      "BIP 389 multipath lengths differ between keys",
      "wsh(multi(2,[1cf0bf7e/48h/0h/0h/2h]xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/<0;1>/*,[4fc1dd4a/48h/0h/0h/2h]xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj/<1;2;3>/*))",
      /cannot read/,
    ],
  ];

  test.each(refused)("%s", (_, text, reason) => {
    expect(() => parseWallet(text)).toThrow(DescriptorError);
    expect(() => parseWallet(text)).toThrow(reason);
  });

  test("a changed character fails Core's checksum", () => {
    const text = cases[0].forms.multipath;
    expect(() => parseWallet(text.replace("1cf0bf7e", "1cf0bf7f"))).toThrow(/checksum/);
  });
});
