# Changes

What each published version of Multisig changed, newest first. A version is published when its signed bundle,
`app.ghostlyapp`, is committed here and the Ghostly store lists it ([docs/PUBLISHING.md](docs/PUBLISHING.md)).

## Unreleased (0.1.0)

- Reads `wsh` and `sh(wsh)` multisig descriptors (`multi` and `sortedmulti`, 2-15 keys), checksum checked.
- Air-gapped signers (Passport, Keystone, Jade, Sparrow): the PSBT as an animated `ur:crypto-psbt` QR code, the
  wallet as a `ur:bytes` QR of Coldcard's multisig file, and the signed PSBT back from a microSD file (binary or text)
  or pasted UR text. Own UR encoder: every part equal to @ngraveio/bc-ur's, pure and mixed.
- Reads Caravan's wallet file (P2WSH and P2SH-P2WSH) as the `sortedmulti` descriptor it describes, on the network
  it names; its addresses match Caravan's own for Caravan's fixture wallets. Legacy P2SH is refused.
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
- Reads Liana wallets (P2WSH miniscript: `wsh(or_d(pk(A),and_v(v:pkh(B),older(N))))` and its multi-key, multi-path
  forms, keys at `<0;1>`, `<2;3>`...). Change is re-derived from the miniscript; signers are named per co-signer however
  many paths their key is on; "missing" and "fully signed" follow the spending paths, not k-of-n; the witness is the
  smallest one the signatures and timelocks satisfy, checked by running it. A spend through a recovery path is flagged
  with its timelock. Taproot Liana wallets are refused ("not supported yet").
- Tested against Liana 16.0 (lianad, the release binary) on regtest: a primary-path and a recovery-path spend that
  lianad created, merged and broadcast, co-signed by Bitcoin Core wallets; the app finalises each to lianad's transaction.
