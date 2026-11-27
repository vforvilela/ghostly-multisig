# Design: multisig PSBT relay for ghostly (v1)

Working name: ghostly-multisig. 1 page. Status: built (v0.1.0, unpublished), 2026-11-27. Frames as built: [protocol.md](protocol.md).

## Problem
Co-signers move PSBTs by USB stick, email or a vendor server (Nunchuk). ghostly already has an encrypted 1:1 chat between them.

## Scope v1
- **Does:** carries a PSBT between co-signers, shows what it spends, counts signatures, warns when the transaction changed.
- **Doesn't:** sign, hold keys, broadcast, use the network. Signing stays in Sparrow or a hardware wallet.
- Manifest: `"permissions": ["chat"]`. No `internet`.

## Flow (2-of-3, chats are 1:1)
1. Alice pastes the wallet descriptor once per chat. The app stores it (per-chat storage).
2. Alice creates the PSBT in Sparrow, signs, pastes the base64 into the app → sent to Bob.
3. Bob sees the summary, copies the PSBT to Sparrow, signs, and pastes it back.
4. Either side sees "2 of 2 needed: complete" → broadcast from Sparrow.

## Frames
`{"p":"multisig","v":1,"k":<kind>,...}`. Kinds:
- `hello`: wallet id only (the descriptor is never sent; built instead of `desc`).
- `psbt`: `id` (unsigned txid), `n`/`of` chunk index, `d` base64 chunk.
- `ack`: `id`, signatures still missing.
Split if a frame is >12 KiB (limit 16 KiB). The fixtures are ~2 KB.

## Display (honest by construction)
- Every output: address + amount. Change only if its script re-derives from the stored descriptor.
- Fee = Σ `witness_utxo` − Σ outputs. Missing UTXO data → "fee unknown", in red.
- Pin the unsigned txid on first receipt. A different txid → full-screen warning "different transaction".
- Footer, always shown: "Check the amounts on your hardware wallet screen."

## Library
`@scure/btc-signer` 2.4.1 for PSBTs. It has no descriptor parser: `src/descriptor.ts` is our own (BIP-380 checksum, SLIP-132).

## Tests
`test/fixtures/` (regtest). Vitest: parse, fee, change detection, tamper warning. Playwright: two-tab relay.

## Open
- Paste: Ctrl+V in, Ctrl+C out work in the runner sandbox (Chromium 145, WebKit 27.2; 24.6 KB OK). App must use a `<textarea>` + `paste` event: `navigator.clipboard` and `execCommand("paste")` are removed. Desktop WebView not tested.
- PSBT v2 from Sparrow: parse or reject?
- QR display for air-gapped signers: v2.
