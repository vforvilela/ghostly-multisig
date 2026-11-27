// scripts/bundle.mjs: the manifest it expects from ghostly-app.json and a build, and what it flags in one that is not.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { digestOf, expected, PUBLISHER, problems, SOURCE } from "../../scripts/bundle.mjs";

const source = JSON.parse(readFileSync(new URL("../../ghostly-app.json", import.meta.url), "utf8"));
const page = new TextEncoder().encode("<!doctype html><title>Multisig</title>");

describe("the bundle check", () => {
  it("names this repository's bundle in the manifest's sources", () => {
    expect(source.sources).toContain(SOURCE);
    expect(source.permissions).toEqual(["chat"]);
  });

  it("flags a different page, publisher or field", () => {
    const good = expected(source, page, 1);
    const other = new TextEncoder().encode("<!doctype html>changed");
    expect(problems({ ...good, files: expected(source, other, 1).files }, source, page).some((p) => p.includes("index.html"))).toBe(true);
    expect(problems({ ...good, publisher: "x" + PUBLISHER }, source, page).some((p) => p.includes("another publisher"))).toBe(true);
    expect(problems({ ...good, title: "Other" }, source, page).some((p) => p.startsWith("title"))).toBe(true);
  });

  it("refuses to pass while the key and repository are placeholders", () => {
    const found = problems(expected(source, page, 1), source, page);
    if (PUBLISHER.startsWith("REPLACE")) expect(found[0]).toMatch(/placeholders/);
    else expect(found).toEqual([]);
  });

  it("gives the digest of the canonical manifest, whatever the key order", () => {
    const m = expected(source, page, 3);
    const reversed = Object.fromEntries(Object.entries(m).reverse());
    expect(digestOf(reversed)).toBe(digestOf(m));
  });
});
