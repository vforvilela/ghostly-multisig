/**
 * The page: plain DOM, redrawn from the controller's state. The four text boxes (descriptor, PSBT in, PSBT out, signed
 * transaction) are made once and kept across redraws, so a redraw never loses what the person typed or selected.
 *
 * Copy and paste go through the keyboard only: the runner removes navigator.clipboard and execCommand (see
 * docs/design.md), and a native Ctrl+V into a textarea and Ctrl+C out of one both work.
 */
import type { MultisigController, State } from "./app.ts";
import type { OutputInfo, Summary, Warning } from "./psbt.ts";
import type { Network } from "./psbt.ts";
import { fill, type Strings } from "./strings.ts";
import { MAX_PSBT_TEXT, toBase64 } from "./psbt.ts";
import { coldcardFile, fingerprints, walletSpendPaths, type Wallet } from "./descriptor.ts";
import { QrPanel } from "./qr.ts";

type Child = Node | string | null | undefined | false;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const c of children) if (c) el.append(c);
  return el;
}

function button(label: string, onClick: () => void, cls = ""): HTMLButtonElement {
  const b = h("button", { type: "button", class: cls }, label);
  b.addEventListener("click", onClick);
  return b;
}

/** Satoshis as BTC with all 8 decimals, grouped for reading: 0.4999 9412 BTC. */
export function formatBtc(sats: bigint): string {
  const neg = sats < 0n;
  const abs = neg ? -sats : sats;
  const whole = (abs / 100_000_000n).toString();
  const frac = (abs % 100_000_000n).toString().padStart(8, "0");
  return `${neg ? "-" : ""}${whole}.${frac.slice(0, 4)} ${frac.slice(4)} BTC`;
}

const short = (id: string) => `${id.slice(0, 8)}…${id.slice(-8)}`;

function selectAllOnFocus(area: HTMLTextAreaElement): void {
  area.addEventListener("focus", () => area.select());
  area.addEventListener("click", () => area.select());
}

/** A textarea that reads a PSBT on paste (and on its button). */
function pasteBox(placeholder: string, areaLabel: string, label: string, onText: (text: string) => void): { area: HTMLTextAreaElement; go: HTMLButtonElement } {
  const area = h("textarea", { rows: "3", spellcheck: "false", autocomplete: "off", placeholder, "aria-label": areaLabel });
  const go = button(label, () => {
    if (area.value.trim()) onText(area.value);
  });
  area.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain");
    if (!text) return;
    event.preventDefault();
    area.value = text;
    onText(text);
  });
  return { area, go };
}

export function mountMultisig(root: HTMLElement, app: MultisigController, s: Strings): void {
  // ---------- the kept boxes ----------
  const descriptor = h("textarea", { rows: "4", spellcheck: "false", autocomplete: "off", placeholder: s.walletPlaceholder, "aria-label": s.descriptorBox });
  const network = h("select", { "aria-label": s.network });
  for (const n of ["test", "regtest", "main"] as Network[]) network.append(h("option", { value: n }, s[`net_${n}`]));
  const firstPaste = pasteBox(s.pastePlaceholder, s.psbtBox, s.read, (text) => void app.paste(text).then(() => (firstPaste.area.value = "")));
  const signedPaste = pasteBox(s.pastePlaceholder, s.signedBox, s.pasteSigned, (text) => void app.paste(text).then(() => (signedPaste.area.value = "")));
  const copyOut = h("textarea", { rows: "3", readonly: "", spellcheck: "false", "aria-label": s.copyBox, class: "mono" });
  selectAllOnFocus(copyOut);
  const raw = h("textarea", { rows: "3", readonly: "", spellcheck: "false", "aria-label": s.rawBox, class: "mono" });
  selectAllOnFocus(raw);
  let editingWallet = false;
  // Air-gapped signers: the PSBT and the wallet as animated QR codes, and a signed PSBT back from a microSD file.
  let showQr = false;
  let showWalletQr = false;
  const partOf = (n: number, count: number) => fill(s.qrPart, { n, count });
  const psbtQr = new QrPanel(s.qrLabel, partOf);
  const walletQr = new QrPanel(s.walletQrLabel, partOf);
  const fileIn = h("input", { type: "file", accept: ".psbt,.txt,text/plain,application/octet-stream", hidden: "", "aria-label": s.openFile });
  fileIn.addEventListener("change", () => {
    const file = fileIn.files?.[0];
    fileIn.value = "";
    if (file) void file.slice(0, MAX_PSBT_TEXT + 1).arrayBuffer().then((b) => app.paste(new Uint8Array(b)));
  });
  const openFile = () => button(s.openFile, () => fileIn.click());

  const live = h("div", { class: "notice", role: "status", "aria-live": "polite" });
  const body = h("main", { class: "app" });
  root.replaceChildren(body, fileIn);

  const redraw = (state: State) => {
    if (!state.ready) {
      body.replaceChildren(h("p", { class: "muted" }, s.loading));
      return;
    }
    const parts: Child[] = [h("h1", {}, s.title), peerLine(state, s)];
    parts.push(noticeLine(state, s, () => app.dismiss(), live));
    parts.push(walletSection(state));
    parts.push(txSection(state));
    parts.push(h("footer", {}, s.footer));
    body.replaceChildren(...parts.filter((p): p is Node => !!p));
    if (state.conflict) body.append(conflictDialog(state));
  };

  function walletSection(state: State): HTMLElement {
    const sec = h("section", { class: "card", "aria-labelledby": "wallet-h" }, h("h2", { id: "wallet-h" }, s.walletHeading));
    const w = state.wallet;
    if (w && !editingWallet) {
      sec.append(
        h(
          "p",
          { class: "wallet-line" },
          ...(w.policy || w.taproot
            ? [h("strong", {}, "Miniscript"), ` · ${w.taproot ? "Taproot" : w.script === "wsh" ? "P2WSH" : "P2SH-P2WSH"}`, h("br"), walletPaths(w, s)]
            : [
                h("strong", {}, fill(s.walletSummary, { k: w.threshold, n: w.keys.length })),
                ` · ${w.script === "wsh" ? "P2WSH" : "P2SH-P2WSH"} · `,
                ...w.keys.flatMap((k, i) => [i ? " " : "", h("code", {}, k.fingerprint)]),
              ]),
        ),
        h("p", { class: "muted small" }, `${s.walletId}: `, h("code", {}, w.id), ` · ${s.network}: ${s[`net_${state.network}`]}`),
      );
      const row = h("div", { class: "row" });
      if (w.chain === "test") {
        network.value = state.network;
        network.onchange = () => void app.setNetwork(network.value as Network);
        row.append(network);
      }
      row.append(
        button(s.changeWallet, () => {
          editingWallet = true;
          descriptor.value = state.descriptor;
          redraw(app.state);
        }),
        button(showWalletQr ? s.hideQr : s.walletQr, () => {
          showWalletQr = !showWalletQr;
          redraw(app.state);
        }),
      );
      sec.append(row);
      if (showWalletQr) {
        try {
          const file = new TextEncoder().encode(coldcardFile(w));
          sec.append(h("p", { class: "muted small" }, s.walletQrHelp), walletQr.show("bytes", file));
        } catch (e) {
          sec.append(h("p", { class: "warn small" }, (e as Error).message));
        }
      } else walletQr.stop();
      return sec;
    }
    sec.append(h("p", { class: "muted small" }, s.walletHelp), descriptor);
    network.value = state.network === "main" ? "test" : state.network;
    network.onchange = null;
    const row = h("div", { class: "row" }, network);
    row.append(
      button(
        s.useWallet,
        () =>
          void app.setWallet(descriptor.value, network.value as Network).then((ok) => {
            if (ok) {
              editingWallet = false;
              redraw(app.state);
            }
          }),
        "primary",
      ),
    );
    if (w) {
      row.append(
        button(s.dismiss, () => {
          editingWallet = false;
          redraw(app.state);
        }),
        button(s.forgetWallet, () => {
          editingWallet = false;
          void app.forgetWallet();
        }, "danger-btn"),
      );
    }
    sec.append(row);
    return sec;
  }

  function txSection(state: State): HTMLElement {
    const sec = h("section", { class: "card", "aria-labelledby": "tx-h" }, h("h2", { id: "tx-h" }, s.txHeading));
    const current = state.current;
    if (!current) {
      sec.append(h("p", { class: "muted small" }, s.pasteHelp), firstPaste.area, h("div", { class: "row" }, firstPaste.go, openFile()));
      return sec;
    }
    if (!current.summary) sec.append(h("p", { class: "warn" }, s.needWallet));
    else sec.append(...summaryView(current.summary, state));

    // The contact.
    if (state.inChat) {
      let status = s.notSent;
      if (current.peerMissing !== null) status = current.peerMissing === 0 ? s.peerHoldsDone : fill(s.peerHolds, { m: current.peerMissing });
      else if (current.send === "queued") status = s.queued;
      else if (current.send === "sent") status = s.sent;
      sec.append(
        h("h3", {}, s.contact),
        h("p", { class: "send-status", "data-send": current.send }, status),
        h("div", { class: "row" }, button(current.send === "unsent" ? s.send : s.sendAgain, () => void app.send(), "primary")),
      );
    }

    const rawHex = app.rawTransaction();
    if (rawHex) {
      if (raw.value !== rawHex) raw.value = rawHex;
      sec.append(h("h3", {}, s.rawHeading), h("p", { class: "muted small" }, s.rawHelp), raw);
    } else {
      const b64 = toBase64(current.tx);
      if (copyOut.value !== b64) copyOut.value = b64;
      sec.append(
        h("h3", {}, s.copyHeading),
        h("p", { class: "muted small" }, s.copyHelp),
        copyOut,
        h(
          "div",
          { class: "row" },
          button(showQr ? s.hideQr : s.showQr, () => {
            showQr = !showQr;
            redraw(app.state);
          }),
        ),
      );
      if (showQr) sec.append(h("p", { class: "muted small" }, s.qrHelp), psbtQr.show("crypto-psbt", current.tx.toPSBT()));
      sec.append(
        h("h3", {}, s.pasteSigned),
        h("p", { class: "muted small" }, s.pasteSignedHelp),
        signedPaste.area,
        h("div", { class: "row" }, signedPaste.go, openFile()),
      );
    }
    if (rawHex || !showQr) psbtQr.stop();
    sec.append(h("div", { class: "row end" }, button(s.done, () => void app.clear())));
    return sec;
  }

  function summaryView(sum: Summary, state: State): Node[] {
    const w = state.wallet!;
    const out: Node[] = [];
    if (sum.warnings.length) {
      out.push(h("ul", { class: "warnings", role: "alert" }, ...sum.warnings.map((x) => h("li", {}, warningText(x, s)))));
    }
    // A miniscript wallet's paths each need their own signers: count those who signed, and those still missing.
    const paths = !!(w.policy || w.taproot);
    const have = paths ? sum.signers.length : w.threshold - sum.missing;
    const need = paths ? have + sum.missing : w.threshold;
    out.push(
      h("h3", {}, s.signatures),
      h("p", { class: sum.complete ? "ok" : "" }, sum.complete ? s.ready : fill(s.signedOf, { have, need })),
      h(
        "ul",
        { class: "signers" },
        ...fingerprints(w).map((f) => {
          const signed = sum.signers.includes(f);
          return h("li", { "data-signed": String(signed) }, h("code", {}, f), ` ${signed ? s.signedMark : s.unsignedMark}`);
        }),
      ),
      h("h3", {}, s.sends),
      h("ul", { class: "outputs" }, ...sum.outputs.map((o) => outputRow(o))),
      h("h3", {}, s.fee),
      h(
        "p",
        {},
        sum.fee === null ? s.feeUnknown : `${formatBtc(sum.fee)} · ${fill(s.feeRate, { rate: (Number(sum.fee) / sum.vsize).toFixed(1) })}`,
      ),
      h(
        "details",
        {},
        h("summary", {}, `${s.inputs} (${sum.inputs.length})`),
        h(
          "ul",
          { class: "inputs" },
          ...sum.inputs.map((i) =>
            h(
              "li",
              { class: i.mine ? "" : "bad" },
              fill(i.mine ? s.input : s.inputForeign, { amount: i.amount === null ? "?" : formatBtc(i.amount), outpoint: short(i.outpoint) }),
            ),
          ),
        ),
      ),
      h("p", { class: "muted small" }, `${s.txid}: `, h("code", { class: "txid" }, sum.txid)),
    );
    return out;
  }

  function outputRow(o: OutputInfo): HTMLElement {
    const label = { external: s.pay, change: s.change, receive: s.receive, "fake-change": s.fakeChange }[o.kind];
    return h(
      "li",
      { "data-kind": o.kind },
      h("span", { class: "amount" }, formatBtc(o.amount)),
      h("span", { class: "label" }, label),
      h("code", { class: "address" }, o.address),
    );
  }

  function conflictDialog(state: State): HTMLElement {
    const c = state.conflict!;
    const brief = (sum: Summary | null, id: string) =>
      h(
        "div",
        { class: "brief" },
        h("code", {}, short(id)),
        sum ? h("ul", { class: "outputs" }, ...sum.outputs.map((o) => outputRow(o))) : null,
        sum && sum.fee !== null ? h("p", {}, `${s.fee}: ${formatBtc(sum.fee)}`) : null,
      );
    return h(
      "div",
      { class: "overlay", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "conflict-h" },
      h(
        "div",
        { class: "dialog" },
        h("h2", { id: "conflict-h" }, s.conflictHeading),
        h("p", {}, c.from === "peer" ? s.conflictFromPeer : s.conflictFromPaste),
        h("h3", {}, s.current),
        brief(state.current!.summary, state.current!.tx.id),
        h("h3", {}, s.incoming),
        brief(c.summary, c.tx.id),
        h("div", { class: "row" }, button(s.keep, () => void app.resolve("keep"), "primary"), button(s.replace, () => void app.resolve("replace"))),
      ),
    );
  }

  app.subscribe(redraw);
}

function peerLine(state: State, s: Strings): HTMLElement | null {
  if (!state.inChat) return h("p", { class: "muted" }, s.alone);
  const p = state.peer;
  const bits: string[] = [p.open ? s.peerOpen : s.peerClosed];
  let cls = p.open ? "peer open" : "peer";
  if (p.open && p.wallet !== undefined && state.wallet) {
    if (p.wallet === null) bits.push(s.peerNoWallet);
    else if (p.wallet === state.wallet.id) bits.push(s.peerSameWallet);
    else {
      bits.push(s.peerOtherWallet);
      cls += " mismatch";
    }
  }
  return h("p", { class: cls }, bits.join(" · "));
}

function noticeLine(state: State, s: Strings, dismiss: () => void, live: HTMLElement): HTMLElement {
  const n = state.notice;
  let text = "";
  if (n) {
    switch (n.k) {
      case "merged":
        text = n.by.length ? fill(s.n_mergedBy, { by: n.by.join(", ") }) : s.n_merged;
        break;
      case "bad-sigs":
        text = fill(s.n_badSigs, { n: String(n.n) });
        break;
      case "same":
        text = s.n_same;
        break;
      case "received":
        text = s.n_received;
        break;
      case "bad-frame":
        text = s.n_badFrame;
        break;
      case "newer-version":
        text = s.n_newer;
        break;
      case "bad-psbt":
        text = fill(s.n_badPsbt, { why: n.why });
        break;
      case "bad-wallet":
        text = fill(s.n_badWallet, { why: n.why });
        break;
      case "send-failed":
        text = s.n_sendFailed;
        break;
    }
  }
  live.replaceChildren();
  live.dataset.kind = n?.k ?? "";
  if (text) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "link";
    b.textContent = s.dismiss;
    b.addEventListener("click", dismiss);
    live.append(text, " ", b);
  }
  return live;
}

export function warningText(w: Warning, s: Strings): string {
  switch (w.k) {
    case "foreign-input":
      return fill(s.w_foreign, { n: w.n + 1 });
    case "fake-change":
      return fill(s.w_fake, { n: w.n + 1 });
    case "no-amount":
      return fill(s.w_noAmount, { n: w.n + 1 });
    case "amount-mismatch":
      return fill(s.w_amountMismatch, { n: w.n + 1 });
    case "sighash":
      return fill(s.w_sighash, { n: w.n + 1 });
    case "high-fee":
      return s.w_highFee;
    case "no-change-back":
      return s.w_noChange;
    case "recovery-path":
      return fill(s.w_recovery, { blocks: w.blocks });
  }
}

/** A miniscript wallet's spending paths, e.g. "2 of a, b · after 1000 blocks, 1 of c" (a Taproot one's key path first). */
export function walletPaths(w: Wallet, s: Strings): string {
  return walletSpendPaths(w)
    .map((p) => {
      const who = p.groups
        .map((g) => fill(s.walletPath, { k: g.k, keys: [...new Set(g.keys.map((i) => w.keys[i].fingerprint))].join(", ") }))
        .join(" + ");
      return p.older.length ? fill(s.walletPathAfter, { blocks: Math.max(...p.older), who }) : who;
    })
    .join(" · ");
}
