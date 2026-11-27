# Ghostly Multisig

Pass a multisig transaction between co-signers in a [Ghostly](https://github.com/MiguelMedeiros/ghostly) chat. Paste
your wallet's output descriptor and a PSBT: Multisig shows where every satoshi goes, checks the change against your
own wallet, counts the signatures, and passes the PSBT to your contact over the chat, merging the signatures you each
add. When enough co-signers have signed, it gives the signed transaction in hex for any wallet or node to broadcast.

Multisig never signs, never sees a private key, and never touches the network: signing stays in your coordinator
(Sparrow, Specter, Bitcoin Core) and your hardware wallet. Check every amount and address on the hardware wallet's
screen before you sign.

It is a Ghostly mini-app ([WISP 1200](https://github.com/MiguelMedeiros/ghostly/blob/dev/docs/wisps/1200-marketplace.md)):
one self-contained HTML file, `"permissions": ["chat"]` only.

## What it checks

- **Change.** An output counts as yours only if its script re-derives from your descriptor at the path the PSBT
  claims. A PSBT that names your key path on someone else's script shows **"Claims to be your change but is NOT"**
  (`test/unit/psbt.test.ts`, the swapped-change test).
- **Inputs.** Each input must re-derive from your wallet; amounts from `witness_utxo` and `non_witness_utxo` must agree.
- **Fee.** Shown in BTC and sat/vB; flagged when over 1000 sat/vB, over 10% of the inputs, or negative.
- **Signatures.** A signature counts only if it is by a key the descriptor derives for that input and verifies
  (BIP 143). One that does not is taken out on arrival and the person is told (`test/unit/signatures.test.ts`). Any
  sighash other than `ALL` is flagged.
- **Same transaction.** A PSBT for a different unsigned txid is never merged: you pick which one to keep.

## Supported wallets

`wsh(multi|sortedmulti(...))` and `sh(wsh(...))`, 2 to 15 keys, with key origins and a ranged `/*`
(`<0;1>/*` or one line per branch), on mainnet, testnet/signet or regtest. xpub/tpub and SLIP-132 (Zpub, Vpub...)
keys are read. Taproot and legacy P2SH multisig are not.

## Build

Node 22 or later.

```sh
npm ci
npm run typecheck
npm test               # descriptors, PSBT checks, protocol, two sides on a mock broker, the icon and the bundle check
npm run build          # dist/index.html, the whole app in one file
npm run dev            # outside Ghostly, a stand-in broker that keeps nothing
npm run test:browser   # the built page in Chromium and WebKit (npx playwright install chromium webkit once)
```

`npm run test:browser` runs two chat sides inside `<iframe sandbox="allow-scripts">` under the web runner's CSP: Alice
pastes a PSBT signed by one key, Bob receives it, pastes his signed copy, both see "Fully signed" and the raw
transaction, and no CSP violation is reported. It also checks a conflicting PSBT and a 360 px phone width.

### Checked by hand

- Paste in and copy out (Ctrl+V / Ctrl+C) in the runner sandbox, Chromium and WebKit: `test/sandbox-paste/`.
- **Not yet:** the desktop client's WebView, and a full round trip with Sparrow and a hardware wallet.

## Languages

English, Portuguese and Spanish. Error reasons from descriptor and PSBT parsing stay in English: they quote
Bitcoin terms a translation would blur.

## Docs

- [docs/design.md](docs/design.md): scope and choices.
- [docs/protocol.md](docs/protocol.md): the chat messages, for another client.
- [docs/PUBLISHING.md](docs/PUBLISHING.md): signing and listing a version.
- [CHANGES.md](CHANGES.md).

## License

MIT. `src/vendor/miniApp.ts` and the release scripts are adapted from Ghostly and Ghostly Chess (MIT, Miguel Medeiros).
