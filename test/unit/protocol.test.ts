import { describe, expect, it } from "vitest";
import { CHUNK_CHARS, MAX_MESSAGE_BYTES, MAX_PARTS, Reassembler, chunk, frame, parseMessage } from "../../src/protocol.ts";

const ID = "ab".repeat(32);
const B64 = "QUJD".repeat(9000); // 36000 characters: three parts

describe("protocol", () => {
  it("splits and rebuilds a large PSBT in any order", () => {
    const parts = chunk(ID, B64);
    expect(parts).toHaveLength(3);
    for (const p of parts) expect(new TextEncoder().encode(JSON.stringify(frame(p))).length).toBeLessThan(MAX_MESSAGE_BYTES);
    const r = new Reassembler();
    expect(r.add(parts[2] as never)).toBeNull();
    expect(r.add(parts[0] as never)).toBeNull();
    expect(r.add(parts[1] as never)).toBe(B64);
  });

  it("starts over when parts of another transaction arrive", () => {
    const r = new Reassembler();
    const [first] = chunk(ID, B64);
    r.add(first as never);
    const other = chunk("cd".repeat(32), "QUJD");
    expect(r.add(other[0] as never)).toBe("QUJD");
  });

  it("round-trips every kind through the frame", () => {
    for (const m of [
      { k: "hello", w: null },
      { k: "hello", w: "0123456789abcdef", re: 1 },
      { k: "psbt", id: ID, n: 0, of: 1, d: "QUJD" },
      { k: "ack", id: ID, m: 2 },
    ] as const) {
      expect(parseMessage(JSON.parse(JSON.stringify(frame(m))))).toEqual({ ok: true, message: m });
    }
  });

  it("refuses anything out of shape", () => {
    const bad = [
      null,
      [],
      { p: "chess", v: 1, k: "hello", w: null },
      { p: "multisig", v: 0, k: "hello", w: null },
      { p: "multisig", v: 1, k: "hello", w: "XYZ" },
      { p: "multisig", v: 1, k: "psbt", id: ID, n: 1, of: 1, d: "QUJD" },
      { p: "multisig", v: 1, k: "psbt", id: ID, n: 0, of: MAX_PARTS + 1, d: "QUJD" },
      { p: "multisig", v: 1, k: "psbt", id: ID, n: 0, of: 1, d: "<script>" },
      { p: "multisig", v: 1, k: "psbt", id: ID.toUpperCase(), n: 0, of: 1, d: "QUJD" },
      { p: "multisig", v: 1, k: "ack", id: ID, m: -1 },
      { p: "multisig", v: 1, k: "nope" },
    ];
    for (const b of bad) expect(parseMessage(b).ok, JSON.stringify(b)).toBe(false);
    expect(parseMessage({ p: "multisig", v: 2, k: "hello", w: null })).toEqual({ ok: false, reason: "newer-version" });
    expect(parseMessage({ p: "multisig", v: 1, k: "psbt", x: "a".repeat(MAX_MESSAGE_BYTES) })).toEqual({ ok: false, reason: "too-big" });
    expect(() => chunk(ID, "A".repeat(CHUNK_CHARS * MAX_PARTS + 1))).toThrow();
  });
});
