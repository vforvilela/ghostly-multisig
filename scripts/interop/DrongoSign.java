// A co-signer that signs the way Sparrow does: drongo's Wallet.sign, with a BIP 39 seed keystore in a watch-only
// multisig wallet built from the descriptor. Used by scripts/interop/signing.mjs; needs drongo on the classpath.
//
//   java -cp <drongo classpath> DrongoSign.java xpub "<mnemonic>" <path>            -> "<fingerprint> <tpub>"
//   java -cp <drongo classpath> DrongoSign.java sign "<mnemonic>" <path> "<descriptor>" < psbt.b64 > signed.b64
//
// Regtest only.
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class DrongoSign {
    public static void main(String[] args) throws Exception {
        Network.set(Network.REGTEST);
        DeterministicSeed seed = new DeterministicSeed(args[1], "", 0, DeterministicSeed.Type.BIP39);
        Keystore signer = Keystore.fromSeed(seed, PolicyType.MULTI_HD, KeyDerivation.parsePath(args[2]));

        if (args[0].equals("xpub")) {
            System.out.println(signer.getKeyDerivation().getMasterFingerprint() + " " + signer.getExtendedPublicKey());
            return;
        }

        Wallet wallet = OutputDescriptor.getOutputDescriptor(args[3]).toWallet();
        List<Keystore> keystores = wallet.getKeystores();
        String fingerprint = signer.getKeyDerivation().getMasterFingerprint();
        int at = -1;
        for (int i = 0; i < keystores.size(); i++) {
            if (keystores.get(i).getKeyDerivation().getMasterFingerprint().equals(fingerprint)) at = i;
        }
        if (at < 0) throw new IllegalArgumentException("the seed is not one of the descriptor's keys");
        signer.setLabel(keystores.get(at).getLabel());
        keystores.set(at, signer);
        if (!wallet.isValid()) throw new IllegalStateException("drongo says the wallet is not valid");

        String text = new String(System.in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        PSBT psbt = PSBT.fromString(text);
        if (wallet.getSigningNodes(psbt).isEmpty()) throw new IllegalStateException("drongo found no input it can sign");
        wallet.sign(psbt);
        System.out.println(psbt.toBase64String());
    }
}
