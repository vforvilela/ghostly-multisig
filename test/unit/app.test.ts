import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { MultisigController } from "../../src/app.ts";
import { chatPair, type MockBroker } from "../mockBroker.ts";
import { CHUNK_CHARS, frame } from "../../src/protocol.ts";
import { readPsbt, toBase64 } from "../../src/psbt.ts";

const fixture = (f: string) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8").trim();
const DESCRIPTOR = fixture("descriptor.txt");
const idOf = (f: string) => readPsbt(fixture(f)).id;

/** Lets every frame in flight land and every queued job run. */
async function settle(...brokers: MockBroker[]): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await new Promise((r) => setTimeout(r, 0));
    if (i > 5 && brokers.every((b) => b.inFlight === 0)) return;
  }
}

async function pair(walletA = true, walletB = true) {
  const [a, b] = chatPair();
  a.launch();
  b.launch();
  const ca = new MultisigController(a);
  const cb = new MultisigController(b);
  await ca.start();
  await cb.start();
  if (walletA) await ca.setWallet(DESCRIPTOR, "regtest");
  if (walletB) await cb.setWallet(DESCRIPTOR, "regtest");
  await settle(a, b);
  return { a, b, ca, cb };
}

describe("controller", () => {
  it("contacts see that they hold the same wallet", async () => {
    const { a, b, ca, cb } = await pair();
    await settle(a, b);
    expect(ca.state.peer.wallet).toBe(ca.state.wallet!.id);
    expect(cb.state.peer.wallet).toBe(cb.state.wallet!.id);
  });

  it("takes a forged signature out of a pasted PSBT, says so, and sends only the real ones", async () => {
    const { a, b, ca, cb } = await pair();
    const forged = readPsbt(fixture("1-alice.psbt"));
    for (let n = 0; n < forged.inputsLength; n++) {
      const input = forged.getInput(n);
      const signed = input.partialSig![0][0];
      const other = input.bip32Derivation!.find(([pk]) => pk.some((x, i) => x !== signed[i]))![0];
      const sig = new Uint8Array(71);
      sig.set([0x30, 68, 2, 32, 1], 0);
      sig.set([2, 32, 1], 36);
      sig[70] = 1;
      forged.updateInput(n, { partialSig: [[other, sig]] }, true);
    }
    await ca.paste(toBase64(forged));
    expect(ca.state.notice).toEqual({ k: "bad-sigs", n: 2 });
    expect(ca.state.current!.summary!.missing).toBe(1);
    await ca.send();
    await settle(a, b);
    expect(cb.state.current!.summary!.missing).toBe(1);
    expect(cb.rawTransaction()).toBeNull();
  });

  it("relays a PSBT, merges the second signature and finalises", async () => {
    const { a, b, ca, cb } = await pair();
    await ca.paste(fixture("1-alice.psbt"));
    expect(ca.state.current!.summary!.missing).toBe(1);
    await ca.send();
    await settle(a, b);
    expect(cb.state.current!.tx.id).toBe(ca.state.current!.tx.id);
    expect(cb.state.notice).toEqual({ k: "received" });
    expect(ca.state.current!.peerMissing).toBe(1);
    // Bob signs in his coordinator and pastes his half back: the app merges both.
    await cb.paste(fixture("1-bob.psbt"));
    expect(cb.state.notice).toEqual({ k: "merged", by: ["e5ae5b12"] });
    expect(cb.state.current!.summary!.complete).toBe(true);
    expect(cb.rawTransaction()).toMatch(/^02000000/);
    await cb.send();
    await settle(a, b);
    expect(ca.state.current!.summary!.complete).toBe(true);
    expect(cb.state.current!.peerMissing).toBe(0);
  });

  it("waits to send until the contact opens the app", async () => {
    const { a, b, ca, cb } = await pair();
    b.shutdown();
    await settle(a, b);
    expect(ca.state.peer.open).toBe(false);
    await ca.paste(fixture("0-unsigned.psbt"));
    await ca.send();
    expect(ca.state.current!.send).toBe("queued");
    b.launch();
    const cb2 = new MultisigController(b);
    await cb2.start();
    await settle(a, b);
    expect(ca.state.current!.send).toBe("sent");
    expect(cb2.state.current!.tx.id).toBe(ca.state.current!.tx.id);
  });

  it("never swaps in a different transaction without asking", async () => {
    const { a, b, ca, cb } = await pair();
    await ca.paste(fixture("0-unsigned.psbt"));
    await cb.paste(fixture("x-tampered-same-inputs.psbt"));
    await cb.send();
    await settle(a, b);
    expect(ca.state.conflict?.from).toBe("peer");
    expect(ca.state.current!.tx.id).toBe(idOf("0-unsigned.psbt"));
    await ca.resolve("keep");
    expect(ca.state.conflict).toBeNull();
    expect(ca.state.current!.tx.id).toBe(idOf("0-unsigned.psbt"));
    await ca.paste(fixture("x-tampered-same-inputs.psbt"));
    expect(ca.state.conflict?.from).toBe("paste");
    await ca.resolve("replace");
    expect(ca.state.current!.tx.id).not.toBe(idOf("0-unsigned.psbt"));
  });

  it("keeps the wallet and the transaction across a reopen", async () => {
    const { a, b, ca } = await pair();
    await ca.paste(fixture("1-alice.psbt"));
    const id = ca.state.current!.tx.id;
    a.shutdown();
    a.launch();
    const again = new MultisigController(a);
    await again.start();
    await settle(a, b);
    expect(again.state.wallet!.id).toBe(ca.state.wallet!.id);
    expect(again.state.network).toBe("regtest");
    expect(again.state.current!.tx.id).toBe(id);
    expect(again.state.current!.summary!.missing).toBe(1);
  });

  it("ignores hostile frames and a PSBT whose txid is not its id", async () => {
    const { a, b, ca } = await pair();
    a.inject({ p: "multisig", v: 1, k: "psbt", id: "x", n: 0, of: 1, d: "AAAA" });
    await settle(a, b);
    expect(ca.state.notice).toEqual({ k: "bad-frame" });
    a.inject({ p: "multisig", v: 9, k: "hello", w: null });
    await settle(a, b);
    expect(ca.state.notice).toEqual({ k: "newer-version" });
    a.inject(frame({ k: "psbt", id: "0".repeat(64), n: 0, of: 1, d: fixture("0-unsigned.psbt") }));
    await settle(a, b);
    expect(ca.state.notice).toEqual({ k: "bad-frame" });
    expect(ca.state.current).toBeNull();
    a.inject({ p: "multisig", v: 1, k: "psbt", id: "0".repeat(64), n: 0, of: 1, d: "A".repeat(CHUNK_CHARS + 1) });
    await settle(a, b);
    expect(ca.state.current).toBeNull();
  });

  it("refuses a wallet it cannot read, with the reason", async () => {
    const { ca } = await pair(false, false);
    expect(await ca.setWallet("wsh(pk(x))", "test")).toBe(false);
    expect(ca.state.notice?.k).toBe("bad-wallet");
    expect(ca.state.wallet).toBeNull();
  });

  it("takes Caravan's wallet file: kept as its descriptor, on the network the file names", async () => {
    const { ca } = await pair(false, false);
    const file = readFileSync(new URL("../vectors/caravan/bitcoin-2-of-2-P2WSH_MAINNET.json", import.meta.url), "utf8");
    expect(await ca.setWallet(file, "test")).toBe(true);
    expect(ca.state.descriptor).toMatch(/^wsh\(sortedmulti\(2,\[00000006\/48h\/0h\/100h\/2h\]xpub/);
    expect(ca.state.network).toBe("main");
    expect(await ca.setWallet(readFileSync(new URL("../vectors/caravan/bitcoin-2-of-2-P2SH_MAINNET.json", import.meta.url), "utf8"), "test")).toBe(false);
    expect(ca.state.notice).toEqual({ k: "bad-wallet", why: "Caravan P2SH wallets are not supported: only P2WSH and P2SH-P2WSH" });
  });

  it("holds a PSBT received before a wallet is set, and reads it once one is", async () => {
    const { a, b, ca, cb } = await pair(true, false);
    await ca.paste(fixture("0-unsigned.psbt"));
    await ca.send();
    await settle(a, b);
    expect(cb.state.current!.summary).toBeNull();
    await cb.setWallet(DESCRIPTOR, "regtest");
    expect(cb.state.current!.summary!.fee).toBe(588n);
  });
});

