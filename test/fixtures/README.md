# Fixtures (regtest, Bitcoin Core v30.2.0, 2026-11-27)

2-of-3 `wsh(sortedmulti)` wallet funded with 3 × 1 BTC. Spend: 1.5 BTC out + change, 2 inputs, 2 sat/vB.

| File | State | Size (base64) |
|---|---|---|
| `0-unsigned.psbt` | 0 sigs | 1888 chars |
| `1-alice.psbt`, `1-bob.psbt` | 1 sig each | 2172 |
| `2-alice-bob.psbt` | 2 sigs, finalized by Core | 1800 |
| `2-combined.psbt` | the two 1-sig PSBTs combined | 2460 |
| `x-tampered-same-inputs.psbt` | same inputs, different destination | — |
| `descriptor.txt` | receive + change descriptors (public keys only) | — |

- Every input has `witness_utxo`, so the fee can be computed offline (5.88e-06 BTC).
- The change output carries `bip32_derivs`.
- `bitcoin-cli combinepsbt` on `0-unsigned` + `x-tampered` fails with error -8 (different transactions).
- Regtest keys only. Never fund on mainnet.
