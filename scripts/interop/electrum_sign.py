"""A co-signer that signs the way Electrum does: Electrum's Multisig_Wallet.sign_transaction, holding one key as a BIP 39
seed and the others as xpubs with their origins. Used by scripts/interop/signing.mjs; run with the Python that has
Electrum installed.

    python -I electrum_sign.py "<mnemonic>" <path> <threshold> <fingerprint>:<tpub> ... < psbt.b64 > out.txt

The cosigners share the signer's path. Electrum keeps no wallet file here and never connects. Regtest only.
"""
import base64
import sys
import tempfile

from electrum import constants, keystore, util
from electrum.bip32 import BIP32Node
from electrum.simple_config import SimpleConfig
from electrum.transaction import tx_from_any
from electrum.wallet import Multisig_Wallet
from electrum.wallet_db import WalletDB

constants.BitcoinRegtest.set_as_network()
loop, stop_loop, loop_thread = util.create_and_start_event_loop()
try:
    mnemonic, path, threshold, *others = sys.argv[1:]
    signer = keystore.from_bip43_rootseed(keystore.bip39_to_seed(mnemonic, passphrase=""), derivation=path, xtype="p2wsh")
    cosigners = []
    for other in others:
        fingerprint, tpub = other.split(":")
        # Electrum wants every cosigner in its p2wsh form (Vpub); a tpub would read as a single-sig key.
        k = keystore.from_xpub(BIP32Node.from_xkey(tpub)._replace(xtype="p2wsh").to_xpub())
        k.add_key_origin(derivation_prefix=path, root_fingerprint=fingerprint)
        cosigners.append(k)

    db = WalletDB("", storage=None, upgrade=False)
    for i, k in enumerate([signer, *cosigners]):
        db.put(f"x{i + 1}", k.dump())
    db.put("wallet_type", f"{threshold}of{len(cosigners) + 1}")
    wallet = Multisig_Wallet(db, config=SimpleConfig({"electrum_path": tempfile.mkdtemp(), "offline": True}))
    wallet.synchronize()

    tx = tx_from_any(sys.stdin.read().strip())
    tx.add_info_from_wallet(wallet)
    before = sum(len(i.sigs_ecdsa) for i in tx.inputs())
    wallet.sign_transaction(tx, password=None)
    if sum(len(i.sigs_ecdsa) for i in tx.inputs()) == before:
        raise SystemExit("Electrum added no signature")
    # Line 1: the PSBT. Line 2: what Electrum itself exports, which is the finished raw transaction once it is complete.
    print(base64.b64encode(tx.serialize_as_bytes(force_psbt=True)).decode())
    print(tx.serialize())
finally:
    loop.call_soon_threadsafe(stop_loop.set_result, 1)
    loop_thread.join(timeout=1)
