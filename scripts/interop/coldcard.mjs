// Writes test/vectors/coldcard.json: the app's Coldcard-format multisig setup file (coldcardFile) read back by the
// parsers of the devices and wallets that import it, each run from its own source:
//
//   cc-*        Coldcard firmware (Coldcard/firmware fab5f64a, 2026-11-17), the unix simulator built from it, headless.
//               Each file goes through the simulator's EXEC test hook to MultisigWallet.from_file (the enrol-time
//               parse and checks, own key derived from the seed) and from_simple_text (the parse alone, without the
//               "my key not included" check). cc-default: simulator seed (0F056943), testnet; cc-abandon:
//               --seed "abandon ... about" (73C5DA0A), testnet; cc-mainnet: simulator seed, --mainnet.
//   sparrow-*   Sparrow (sparrowwallet/sparrow 114389b, 2.5.8, drongo aa75a9b): ColdcardMultisig.importWallet and the
//               FileImport.getExtendedPublicKey it calls, copied verbatim into a harness on drongo, per network.
//   passport-*  Passport (Foundation-Devices/passport2 f51b2ca): MultisigWallet.from_file, check_xpub, import_xpub and
//               the utils.py path helpers, lifted verbatim with ast onto CPython; trezorcrypto's bip32 is embit, the
//               own-key derivation check is stubbed (no seed). XTN and BTC chain.
//   keystone    Keystone 3 (KeystoneHQ/keystone3-firmware bd06fe2): app_bitcoin's parse_wallet_config, the device's
//               fingerprint taken as the file's first key, plus create_multi_sig_address_for_wallet(0, 0), which must
//               be the app's first receive address.
//
//   node scripts/interop/coldcard.mjs files <dir>              the files to feed the parsers (alias-* use the
//                                                              "P2WSH-P2SH" spelling of the nested format)
//   node scripts/interop/coldcard.mjs check <result.json>...         compare what each parser returned, write the vector
//
// Each result.json maps a file name to that parser's output; its own name (cc-default.json, ...) is the label above.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { caravanWallet, coldcardFile, deriveScript, parseWallet } from "../../src/descriptor.ts";
import { addressOf } from "../../src/psbt.ts";

const vectors = new URL("../../test/vectors/", import.meta.url);
const json = (name) => JSON.parse(readFileSync(new URL(name, vectors), "utf8"));
const HARDENED = 0x80000000;
const path = (origin) => ["m", ...origin.map((n) => (n >= HARDENED ? `${n - HARDENED}'` : String(n)))].join("/");

function cases() {
  const out = [];
  const add = (name, descriptor, network) => out.push({ name, descriptor, network });
  add("signing", json("signing.json").descriptor, "regtest");
  for (const [device, v] of Object.entries(json("hardware.json").devices)) add(`hardware-${device}`, v.descriptor, "regtest");
  for (const f of readdirSync(new URL("caravan/", vectors)).sort()) {
    let r;
    try {
      r = caravanWallet(readFileSync(new URL(`caravan/${f}`, vectors), "utf8"));
    } catch {
      continue; // P2SH: the app does not take it
    }
    if (r) add(`caravan-${f.replace(/\.json$/, "")}`, r.descriptor, r.network);
  }
  return out.map((c) => {
    const w = parseWallet(c.descriptor);
    const text = coldcardFile(w);
    const expected = {
      threshold: w.threshold,
      script: w.script,
      keys: w.keys.map((k) => ({ fp: k.fingerprint, path: path(k.origin), xpub: k.xpub })),
      receive0: addressOf(deriveScript(w, 0, 0).script, c.network),
    };
    return { ...c, text, expected };
  });
}

const alias = (text) => text.replace(/^Format: P2SH-P2WSH$/m, "Format: P2WSH-P2SH");

const [mode, ...args] = process.argv.slice(2);
const [dir] = args;
if (mode === "files" && dir) {
  for (const c of cases()) {
    writeFileSync(join(dir, `${c.name}.txt`), c.text);
    if (c.expected.script === "sh-wsh") writeFileSync(join(dir, `alias-${c.name}.txt`), alias(c.text));
  }
} else if (mode === "check" && args.length) {
  // Each parser's output, normalised to { accepted, error } or { accepted, threshold, script, keys[, receive0] }.
  const script = (s) => ({ P2WSH: "wsh", "P2SH-P2WSH": "sh-wsh", P2SH_P2WSH: "sh-wsh", AF_P2WSH: "wsh", AF_P2WSH_P2SH: "sh-wsh", "P2WSH-P2SH": "sh-wsh" })[s] ?? s;
  // Coldcard writes hardened steps as h, the others as '.
  const keys = (ks) => ks.map((k) => ({ fp: k.fp.toLowerCase(), path: k.path.replaceAll("h", "'"), xpub: k.xpub }));
  const read = {
    cc: (r) => {
      const one = (x) => (x.ok ? { accepted: true, name: x.name, threshold: x.M, script: script(x.format), keys: keys(x.keys) } : { accepted: false, error: x.error });
      return { chain: r.chain, device: r.my_xfp, enrol: one(r.from_file), parse: one(r.parse) };
    },
    sparrow: (r) => (r.ok ? { accepted: true, name: r.name, threshold: r.threshold, script: script(r.scriptType), keys: keys(r.keys) } : { accepted: false, error: r.error }),
    passport: (r) => (r.ok ? { accepted: true, name: r.name, threshold: r.M, script: script(r.format), keys: keys(r.keys) } : { accepted: false, error: r.error }),
    keystone: (r) => (r.ok ? { accepted: true, name: r.name, threshold: r.threshold, script: script(r.format), keys: keys(r.keys), receive0: r.receive0 } : { accepted: false, error: r.error }),
  };
  const same = (got, want) =>
    got.threshold === want.threshold && got.script === want.script && JSON.stringify(got.keys) === JSON.stringify(want.keys) && (got.receive0 === undefined || got.receive0 === want.receive0);
  const mark = (got, want) => (got.accepted ? { ...got, matches: same(got, want) } : got);

  const loaded = args.map((f) => ({ label: basename(f, ".json"), data: JSON.parse(readFileSync(f, "utf8")) }));
  const out = { generated: new Date().toISOString().slice(0, 10), cases: {} };
  let bad = 0;
  for (const c of cases()) {
    for (const [file, text] of [[`${c.name}.txt`, c.text], ...(c.expected.script === "sh-wsh" ? [[`alias-${c.name}.txt`, alias(c.text)]] : [])]) {
      const entry = { network: c.network, file: text, expected: c.expected, parsers: {} };
      for (const { label, data } of loaded) {
        if (!data[file]) continue;
        const kind = Object.keys(read).find((k) => label.startsWith(k));
        const got = read[kind](data[file]);
        entry.parsers[label] = kind === "cc" ? { ...got, enrol: mark(got.enrol, c.expected), parse: mark(got.parse, c.expected) } : mark(got, c.expected);
        for (const g of kind === "cc" ? [entry.parsers[label].enrol, entry.parsers[label].parse] : [entry.parsers[label]]) if (g.matches === false) bad++;
      }
      out.cases[file.replace(/\.txt$/, "")] = entry;
    }
  }
  writeFileSync(new URL("coldcard.json", vectors), `${JSON.stringify(out, null, 1)}\n`);
  if (bad) throw new Error(`${bad} parser results decode to a different wallet`);
} else {
  throw new Error("usage: coldcard.mjs files <dir> | check <result.json>...");
}
