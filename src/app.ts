/**
 * The app's state in one chat: the person's wallet, the transaction being signed, and the contact. Every rule that
 * keeps the relay honest lives here, not in the UI:
 *
 * - The wallet is the person's own: pasted by them, never taken from the contact. Contacts compare wallet ids only.
 * - One transaction at a time, pinned by its unsigned txid. A copy with more signatures merges in; a different
 *   transaction (from the contact or pasted) is never merged or swapped in silently: the person chooses.
 * - A PSBT is sent only when the person presses Send. If the contact's app is closed it waits and goes when it opens.
 */
import type { MiniAppApi, MiniAppJson, MiniAppPeerEvent } from "./vendor/miniApp.ts";
import { DescriptorError, caravanWallet, parseWallet, type Wallet } from "./descriptor.ts";
import { PsbtError, combine, finalise, readPsbt, stripInvalid, summarise, toBase64, type Network, type Summary } from "./psbt.ts";
import { Reassembler, chunk, frame, parseMessage, type Message } from "./protocol.ts";
import type { Transaction } from "@scure/btc-signer";

export type SendState = "unsent" | "queued" | "sent";

export interface Current {
  tx: Transaction;
  /** Null until a wallet is set. */
  summary: Summary | null;
  send: SendState;
  /** The signatures the contact's copy still misses, from its ack; null until it acks this txid. */
  peerMissing: number | null;
}

export interface Conflict {
  tx: Transaction;
  summary: Summary | null;
  from: "peer" | "paste";
}

export type Notice =
  /** by: the co-signers whose signatures are now on every input (empty when the wallet is not set). */
  | { k: "merged"; by: string[] }
  /** n: signatures that did not verify, taken out of an incoming PSBT. */
  | { k: "bad-sigs"; n: number }
  | { k: "same" }
  | { k: "received" }
  | { k: "bad-frame" }
  | { k: "newer-version" }
  | { k: "bad-psbt"; why: string }
  | { k: "bad-wallet"; why: string }
  | { k: "send-failed" };

export interface State {
  ready: boolean;
  inChat: boolean;
  wallet: Wallet | null;
  descriptor: string;
  network: Network;
  current: Current | null;
  conflict: Conflict | null;
  peer: { open: boolean; version: string | null; wallet: string | null | undefined };
  notice: Notice | null;
}

const KEY_WALLET = "wallet";
const KEY_TX = "tx";

const NETWORKS: Network[] = ["main", "test", "regtest"];

export class MultisigController {
  private listeners = new Set<(state: State) => void>();
  private reassembler = new Reassembler();
  state: State = {
    ready: false,
    inChat: false,
    wallet: null,
    descriptor: "",
    network: "test",
    current: null,
    conflict: null,
    peer: { open: false, version: null, wallet: undefined },
    notice: null,
  };

  /** Listens from the start, so no frame that arrives while storage loads is lost. */
  constructor(private readonly api: MiniAppApi) {
    api.chat.on("message", (data) => this.queue(() => this.onFrame(data)));
    api.chat.on("peer", (event) => this.queue(() => this.onPeer(event)));
  }

  /** Work in arrival order, after start() has loaded what is stored. */
  private work: Promise<void> = Promise.resolve();
  private started!: () => void;
  private startedPromise = new Promise<void>((resolve) => (this.started = resolve));
  private queue(job: () => Promise<void> | void): Promise<void> {
    this.work = this.work.then(() => this.startedPromise).then(job).catch(() => {});
    return this.work;
  }

  subscribe(listener: (state: State) => void): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => this.listeners.delete(listener);
  }

  private emit(patch: Partial<State> = {}): void {
    this.state = { ...this.state, ...patch };
    for (const listener of [...this.listeners]) listener(this.state);
  }

  async start(): Promise<void> {
    const context = await this.api.context();
    const stored = await this.api.storage.get(KEY_WALLET).catch(() => undefined);
    let wallet: Wallet | null = null;
    let descriptor = "";
    let network: Network = "test";
    if (stored && typeof stored === "object" && !Array.isArray(stored)) {
      const s = stored as { d?: unknown; net?: unknown };
      if (typeof s.d === "string") {
        try {
          wallet = parseWallet(s.d);
          descriptor = s.d;
        } catch {
          // A wallet stored by an older version and no longer read: the person pastes it again.
        }
      }
      if (NETWORKS.includes(s.net as Network)) network = s.net as Network;
    }
    if (wallet?.chain === "main") network = "main";
    this.state = { ...this.state, wallet, descriptor, network, inChat: context.inChat };
    const tx = await this.api.storage.get(KEY_TX).catch(() => undefined);
    if (tx && typeof tx === "object" && !Array.isArray(tx)) {
      const t = tx as { psbt?: unknown; send?: unknown; pm?: unknown };
      if (typeof t.psbt === "string") {
        try {
          const read = stripInvalid(readPsbt(t.psbt)).tx;
          const send: SendState = t.send === "sent" || t.send === "queued" ? t.send : "unsent";
          const peerMissing = typeof t.pm === "number" ? t.pm : null;
          this.state.current = { tx: read, summary: this.summaryOf(read), send, peerMissing };
        } catch {
          await this.api.storage.delete(KEY_TX).catch(() => {});
        }
      }
    }
    this.state.peer = { open: !!context.peer, version: context.peer?.version ?? null, wallet: undefined };
    this.emit({ ready: true });
    this.started();
    if (context.peer) await this.queue(async () => void (await this.greet(false)));
  }

  private summaryOf(tx: Transaction): Summary | null {
    const { wallet, network } = this.state;
    if (!wallet) return null;
    try {
      return summarise(tx, wallet, network);
    } catch {
      return null;
    }
  }

  // ---------- the person's actions ----------

  setWallet(descriptor: string, network: Network): Promise<boolean> {
    let ok = false;
    return this.queue(async () => void (ok = await this.setWalletNow(descriptor, network))).then(() => ok);
  }

  private async setWalletNow(descriptor: string, network: Network): Promise<boolean> {
    let wallet: Wallet;
    let text = descriptor.trim();
    try {
      // A Caravan wallet file is kept as the descriptor it describes, on the network it names.
      const caravan = caravanWallet(text);
      if (caravan) [text, network] = [caravan.descriptor, caravan.network];
      wallet = parseWallet(text);
    } catch (e) {
      this.emit({ notice: { k: "bad-wallet", why: e instanceof DescriptorError ? e.message : String(e) } });
      return false;
    }
    if (wallet.chain === "main") network = "main";
    else if (network === "main") network = "test";
    await this.api.storage.set(KEY_WALLET, { d: text, net: network });
    this.state = { ...this.state, wallet, descriptor: text, network, notice: null };
    this.resummarise();
    if (this.state.peer.open) await this.greet(false);
    return true;
  }

  forgetWallet(): Promise<void> {
    return this.queue(() => this.forgetWalletNow());
  }

  private async forgetWalletNow(): Promise<void> {
    await this.api.storage.delete(KEY_WALLET);
    this.state = { ...this.state, wallet: null, descriptor: "" };
    this.resummarise();
    if (this.state.peer.open) await this.greet(false);
  }

  /** A PSBT the person pasted from their coordinator. */
  paste(text: string): Promise<void> {
    return this.queue(() => this.pasteNow(text));
  }

  private async pasteNow(text: string): Promise<void> {
    let tx: Transaction;
    try {
      tx = readPsbt(text);
    } catch (e) {
      this.emit({ notice: { k: "bad-psbt", why: e instanceof PsbtError ? e.message : String(e) } });
      return;
    }
    await this.take(tx, "paste");
  }

  /** Keep the current transaction, or replace it with the conflicting one. */
  resolve(choice: "keep" | "replace"): Promise<void> {
    return this.queue(() => this.resolveNow(choice));
  }

  private async resolveNow(choice: "keep" | "replace"): Promise<void> {
    const conflict = this.state.conflict;
    if (!conflict) return;
    if (choice === "keep") {
      this.emit({ conflict: null });
      return;
    }
    const current: Current = { tx: conflict.tx, summary: this.summaryOf(conflict.tx), send: "unsent", peerMissing: null };
    this.state = { ...this.state, conflict: null, current, notice: null };
    await this.saveTx();
    if (conflict.from === "peer") await this.ack();
    this.emit();
  }

  /** Drops the transaction (after it was broadcast, or to start over). */
  clear(): Promise<void> {
    return this.queue(() => this.clearNow());
  }

  private async clearNow(): Promise<void> {
    await this.api.storage.delete(KEY_TX);
    this.emit({ current: null, conflict: null, notice: null });
  }

  /** Sends the transaction to the contact now, or when their app opens. */
  send(): Promise<void> {
    return this.queue(() => this.sendNow());
  }

  private async sendNow(): Promise<void> {
    const current = this.state.current;
    if (!current) return;
    if (!this.state.peer.open) {
      current.send = "queued";
      await this.saveTx();
      this.emit();
      return;
    }
    try {
      for (const part of chunk(current.tx.id, toBase64(current.tx))) await this.api.chat.send(frame(part));
      current.send = "sent";
    } catch {
      current.send = "queued";
      this.emit({ notice: { k: "send-failed" } });
    }
    await this.saveTx();
    this.emit();
  }

  /** The signed transaction in hex, when every input has its signatures. */
  rawTransaction(): string | null {
    const current = this.state.current;
    if (!current?.summary?.complete) return null;
    try {
      return finalise(current.tx);
    } catch {
      return null;
    }
  }

  setNetwork(network: Network): Promise<boolean> {
    return this.setWallet(this.state.descriptor, network);
  }

  dismiss(): void {
    this.emit({ notice: null });
  }

  // ---------- transactions ----------

  private async take(incoming: Transaction, from: "peer" | "paste"): Promise<void> {
    // A signature that does not verify never comes in: it would count as signed and then block the real one.
    const { tx, dropped } = stripInvalid(incoming);
    const current = this.state.current;
    if (!current) {
      this.state.current = { tx, summary: this.summaryOf(tx), send: "unsent", peerMissing: null };
      this.state.notice = from === "peer" ? { k: "received" } : null;
    } else if (current.tx.id === tx.id) {
      let merged: Transaction;
      try {
        merged = combine(current.tx, tx);
      } catch (e) {
        this.emit({ notice: { k: "bad-psbt", why: (e as Error).message } });
        return;
      }
      const added = signatureCount(merged) - signatureCount(current.tx);
      const before = current.summary?.signers ?? [];
      if (added > 0) {
        current.tx = merged;
        current.summary = this.summaryOf(merged);
        current.send = "unsent";
      }
      const by = (current.summary?.signers ?? []).filter((f) => !before.includes(f));
      this.state.notice = added > 0 ? { k: "merged", by } : from === "peer" ? { k: "received" } : { k: "same" };
    } else {
      this.emit({ conflict: { tx, summary: this.summaryOf(tx), from }, ...(dropped ? { notice: { k: "bad-sigs", n: dropped } } : {}) });
      return;
    }
    if (dropped) this.state.notice = { k: "bad-sigs", n: dropped };
    await this.saveTx();
    if (from === "peer") await this.ack();
    this.emit();
  }

  private resummarise(): void {
    const { current, conflict } = this.state;
    if (current) current.summary = this.summaryOf(current.tx);
    if (conflict) conflict.summary = this.summaryOf(conflict.tx);
    this.emit();
  }

  private async saveTx(): Promise<void> {
    const current = this.state.current;
    if (!current) return;
    const value: Record<string, MiniAppJson> = { psbt: toBase64(current.tx), send: current.send };
    if (current.peerMissing !== null) value.pm = current.peerMissing;
    await this.api.storage.set(KEY_TX, value).catch(() => {});
  }

  // ---------- the contact ----------

  private async sendFrame(message: Message): Promise<boolean> {
    try {
      await this.api.chat.send(frame(message));
      return true;
    } catch {
      return false;
    }
  }

  private greet(re: boolean): Promise<boolean> {
    return this.sendFrame(re ? { k: "hello", w: this.state.wallet?.id ?? null, re: 1 } : { k: "hello", w: this.state.wallet?.id ?? null });
  }

  private ack(): Promise<boolean> {
    const current = this.state.current;
    if (!current) return Promise.resolve(false);
    const missing = current.summary?.missing ?? 15;
    return this.sendFrame({ k: "ack", id: current.tx.id, m: missing });
  }

  private async onPeer(event: MiniAppPeerEvent): Promise<void> {
    if (!event.open) {
      this.emit({ peer: { open: false, version: null, wallet: undefined } });
      return;
    }
    this.emit({ peer: { open: true, version: event.version, wallet: undefined } });
    await this.greet(false);
    if (this.state.current?.send === "queued") await this.sendNow();
  }

  private async onFrame(data: MiniAppJson): Promise<void> {
    const parsed = parseMessage(data);
    if (!parsed.ok) {
      this.emit({ notice: { k: parsed.reason === "newer-version" ? "newer-version" : "bad-frame" } });
      return;
    }
    const message = parsed.message;
    switch (message.k) {
      case "hello":
        this.emit({ peer: { ...this.state.peer, open: true, wallet: message.w } });
        if (!message.re) await this.greet(true);
        return;
      case "ack": {
        const current = this.state.current;
        if (current && current.tx.id === message.id) {
          current.peerMissing = message.m;
          if (current.send === "queued") current.send = "sent";
          await this.saveTx();
          this.emit();
        }
        return;
      }
      case "psbt": {
        const whole = this.reassembler.add(message);
        if (!whole) return;
        let tx: Transaction;
        try {
          tx = readPsbt(whole);
        } catch (e) {
          this.emit({ notice: { k: "bad-psbt", why: (e as Error).message } });
          return;
        }
        if (tx.id !== message.id) {
          this.emit({ notice: { k: "bad-frame" } });
          return;
        }
        await this.take(tx, "peer");
      }
    }
  }
}

/** Signatures across all inputs; a finalised input counts as one more than any partial set. */
function signatureCount(tx: Transaction): number {
  let n = 0;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    n += input.finalScriptWitness ? 16 : (input.partialSig?.length ?? 0);
  }
  return n;
}
