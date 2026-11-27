# Test vectors

Data from other wallets, so the tests check this app against them and not against itself. The tests read these
files and need no node or network; the scripts regenerate the generated ones.

| File | From | Licence | Made by |
| --- | --- | --- | --- |
| `core-rpc_psbt.json` | bitcoin/bitcoin v30.2, `test/functional/data/rpc_psbt.json` | MIT | copied |
| `bip370.json` | bitcoin/bips, `bip-0370.mediawiki` test vectors | BSD-2-Clause | copied |
| `sparrow/*.txt` | sparrowwallet/sparrow test resources (commit 114389b) | Apache-2.0 | copied |
| `descriptors.json` | keys from drongo `OutputDescriptorTest.java` and `sparrow/cc-multisig-export-*.txt`; addresses from Bitcoin Core `deriveaddresses` | Apache-2.0 (keys) | `scripts/interop/descriptors.mjs` |
| `signing.json` | a regtest spend: Bitcoin Core (key A), sparrowwallet/drongo `Wallet.sign` (key B), Trezor Model T emulator 2.13.1 via HWI (key C) | test data, no keys of value | `scripts/interop/signing.mjs` |
| `electrum.json` | `signing.json`'s spend signed by Electrum 4.8.4 (`Multisig_Wallet.sign_transaction`), finalised by Core | test data | `scripts/interop/electrum.mjs` |
| `hardware.json` | regtest spends of 2-of-3s with Core: Coldcard, BitBox02, Ledger (app-bitcoin 2.5.0, Speculos) and Jade 1.0.36 (QEMU) simulators via HWI 3.2.0, each mined by Core | test data | `scripts/interop/hardware.mjs` |
| `caravan.json` | `@caravan/psbt` 2.1.2 and `@caravan/bitcoin` 0.4.7 on `signing.json`'s spend, and the first addresses of each wallet file in `caravan/` | test data | `scripts/interop/caravan.mjs` |
| `liana.json` | a Liana wallet (three spending paths) run by lianad 16.0 (release binary, signature checked) on regtest: a primary-path and a 10-block recovery-path spend, created, merged, finalised and broadcast by lianad, co-signed by Bitcoin Core v30.2 wallets, mined by Core | test data, fixed seeds | `scripts/interop/liana.mjs` |
| `caravan/*.json` | Caravan's wallet-file fixtures, caravan-bitcoin/caravan `dff6283` (`apps/coordinator/fixtures/caravan/`) | MIT | copied |

## Regenerating

`descriptors.json` needs an offline mainnet and testnet `bitcoind` (`-connect=0 -prune=550 -disablewallet`):

    node scripts/interop/descriptors.mjs -chain=main -rpcport=… -datadir=… -- -chain=test -rpcport=… -datadir=…

`signing.json` needs a fresh regtest `bitcoind` (`-fallbackfee=0.0001`), JDK 22+, and drongo built
(`./gradlew jar`), with its runtime classpath in a file, `hwi` on PATH, and trezor-user-env running
(`docker run --rm --network host ghcr.io/trezor/trezor-user-env`):

    node scripts/interop/signing.mjs <java> <classpath file> -regtest -rpcport=… -datadir=…

`electrum.json` needs Electrum, which is not on PyPI: clone spesmilo/electrum at a release tag, install it into a
venv (`pip install "<clone>[crypto]"`), and give that venv's Python and any regtest `bitcoind`:

    node scripts/interop/electrum.mjs <venv>/bin/python -regtest -rpcport=… -datadir=…

`hardware.json` needs HWI's test simulators (HWI's `test/setup_environment.sh --coldcard --bitbox02 --ledger --jade`; the
Ledger app is built as HWI's CI does, app-bitcoin 2.5.0 in `ghcr.io/ledgerhq/ledger-app-builder`), launched and
initialised as HWI's tests do, and a fresh regtest `bitcoind`. The runner runs `hwi` and `python` where HWI is:

    node scripts/interop/hardware.mjs '["docker","exec","-i","-w","/hwi","<container>","poetry","run"]' coldcard,bitbox02,ledger,jade -regtest -rpcport=… -datadir=…

The BitBox02 needs the wallet's xpubs in the PSBT (the script adds them, as Sparrow does) and a named registration
with the account keypath, which HWI's `registerdescriptor` and `signtx` do not send; the script registers it first.

`caravan.json` needs only the two Caravan packages installed somewhere (`npm install @caravan/psbt @caravan/bitcoin`):

    node scripts/interop/caravan.mjs <that folder>/node_modules

`liana.json` needs Liana's release binary unpacked (`liana-16.0-x86_64-linux-gnu.tar.gz`, checked against
`liana-16.0-shasums.txt` and its signature) and a fresh regtest `bitcoind` (`-fallbackfee=0.0001 -txindex=1`); the
script runs lianad against it in the work folder:

    node scripts/interop/liana.mjs <folder with lianad> <work folder> -regtest -rpcport=… -datadir=…

Every key here is a BIP 39 test mnemonic, a simulator's fixed test seed or a fixed seed: never send real coins to them.
