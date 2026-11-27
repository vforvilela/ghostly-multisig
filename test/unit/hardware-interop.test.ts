/**
 * test/vectors/hardware.json (made by scripts/interop/hardware.mjs): Coldcard, BitBox02, Ledger and Jade simulators, through
 * HWI, as one co-signer of a 2-of-3 with Core. Core finalised and mined each spend; the app must read every copy, name
 * who signed it, and finish the very same transaction from either order of merging.
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { parseWallet } from "../../src/descriptor.ts";
import { combine, finalise, readPsbt, stripInvalid, summarise } from "../../src/psbt.ts";

type Device = { descriptor: string; fingerprints: Record<"core" | "drongo" | "device", string>; unsigned: string; sent: string; signedCore: string; signedDevice: string; final: string; txid: string };
const doc = JSON.parse(readFileSync(new URL("../vectors/hardware.json", import.meta.url), "utf8")) as { devices: Record<string, Device> };
const devices = Object.entries(doc.devices);

test("the vectors cover the four devices", () => {
  expect(devices.map(([name]) => name).sort()).toEqual(["bitbox02", "coldcard", "jade", "ledger"]);
});

describe.each(devices)("%s as a co-signer", (_, d) => {
  const wallet = () => parseWallet(d.descriptor);

  test("the app reads the wallet, and the copy sent to the device", () => {
    expect(wallet().keys.map((k) => k.fingerprint).sort()).toEqual(Object.values(d.fingerprints).sort());
    const s = summarise(readPsbt(d.sent), wallet(), "regtest");
    expect(s.signers).toEqual([]);
    expect(s.warnings).toEqual([]);
  });

  test("its signature passes the app's own check, and is the device's", () => {
    expect(stripInvalid(readPsbt(d.signedDevice)).dropped).toBe(0);
    expect(summarise(readPsbt(d.signedDevice), wallet(), "regtest").signers).toEqual([d.fingerprints.device]);
  });

  test("merged with Core's copy, either order: complete, and the transaction Core mined", () => {
    for (const [a, b] of [[d.signedCore, d.signedDevice], [d.signedDevice, d.signedCore]]) {
      const merged = combine(readPsbt(a), readPsbt(b));
      const s = summarise(merged, wallet(), "regtest");
      expect(s.signers.sort()).toEqual([d.fingerprints.core, d.fingerprints.device].sort());
      expect(s.complete).toBe(true);
      expect(s.warnings).toEqual([]);
      expect(finalise(merged)).toBe(d.final);
    }
  });
});
