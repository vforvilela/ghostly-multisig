# Changes

What each published version of Multisig changed, newest first. A version is published when its signed bundle,
`app.ghostlyapp`, is committed here and the Ghostly store lists it ([docs/PUBLISHING.md](docs/PUBLISHING.md)).

## Unreleased (0.1.0)

- Reads `wsh` and `sh(wsh)` multisig descriptors (`multi` and `sortedmulti`, 2-15 keys), checksum checked.
- Reads a PSBT in base64 or hex and shows outputs, change (re-derived from the descriptor), fee and sat/vB, inputs,
  and who has signed. Warns on foreign inputs, fake change, missing or mismatched amounts, sighash other than ALL,
  a high fee, and no change back.
- Sends the PSBT to the contact over the chat, in parts if needed, queued until they open the app; merges the
  signatures of the same transaction; asks before replacing a different one.
- Verifies every signature before counting it; takes out the ones that do not verify, so a forged signature can
  neither show "Fully signed" nor block the real one.
- Gives the signed transaction in hex once complete. Never signs, never broadcasts.
- English, Portuguese and Spanish.
- Refuses PSBT version 2 (BIP 370) with a plain reason; it must be exported as version 0.
- Takes the `/**` key ending (BIP 388, Sparrow) as `/<0;1>/*`.
- Tested against other wallets: Bitcoin Core's PSBT vectors, BIP 370's vectors, Sparrow's descriptors and Coldcard
  exports (addresses from Core), and a 2-of-3 spend co-signed by Core, Sparrow's drongo and a Trezor emulator (through HWI),
  each pairing accepted by Core.
- Also tested against Electrum 4.8.4 as a co-signer, the Coldcard, BitBox02, Ledger and Jade simulators through HWI (each
  spend mined by Core), and Caravan's own PSBT code (it validates the app's merged signatures).
- A finished raw transaction pasted in (as Electrum exports it once its signature completes the spend) is explained
  as such, instead of "not a PSBT".
- A copy another wallet already finalised: merging it keeps the key paths, names only the keys that signed, and
  finishing it no longer fails.
