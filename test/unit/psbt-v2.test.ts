/** PSBT v2 (BIP 370) is refused whole, valid or not: test/vectors/bip370.json, the BIP's own vectors (BSD-2-Clause). */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { readPsbt } from "../../src/psbt.ts";

const vectors = JSON.parse(readFileSync(new URL("../vectors/bip370.json", import.meta.url), "utf8")) as {
  invalid: { case: string; psbt: string }[];
  valid: { case: string; psbt: string }[];
};

const why = (psbt: string): string => {
  try {
    readPsbt(psbt);
    return "read";
  } catch (e) {
    return (e as Error).message;
  }
};

describe("BIP 370 vectors", () => {
  test.each(vectors.invalid.map((v) => [v.case, v.psbt]))("refuses invalid: %s", (_, psbt) => {
    expect(why(psbt)).not.toBe("read");
  });

  test.each(vectors.valid.map((v) => [v.case, v.psbt]))("refuses valid v2 with a clear reason: %s", (_, psbt) => {
    expect(why(psbt)).toBe("PSBT version 2: export it from your wallet as version 0");
  });
});
