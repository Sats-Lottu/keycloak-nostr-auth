package keycloak.auth.nostr;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;

final class Bip340 {
    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");
    private static final BigInteger FIELD = CURVE.getCurve().getField().getCharacteristic();
    private static final byte[] TAG = sha256("BIP0340/challenge".getBytes(StandardCharsets.US_ASCII));

    private Bip340() {}

    static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) return false;
        BigInteger r = new BigInteger(1, signature, 0, 32);
        BigInteger s = new BigInteger(1, signature, 32, 32);
        if (r.compareTo(FIELD) >= 0 || s.compareTo(CURVE.getN()) >= 0) return false;

        byte[] compressed = new byte[33];
        compressed[0] = 2; // Lift the x-only public key to the point with even y.
        System.arraycopy(publicKey, 0, compressed, 1, publicKey.length);
        try {
            var point = CURVE.getCurve().decodePoint(compressed);
            var hash = sha256Digest();
            hash.update(TAG);
            hash.update(TAG);
            hash.update(Arrays.copyOf(signature, 32));
            hash.update(publicKey);
            BigInteger challenge = new BigInteger(1, hash.digest(message)).mod(CURVE.getN());

            var reconstructed = ECAlgorithms.sumOfTwoMultiplies(
                    CURVE.getG(), s, point, CURVE.getN().subtract(challenge)).normalize();
            return !reconstructed.isInfinity()
                    && !reconstructed.getAffineYCoord().testBitZero()
                    && reconstructed.getAffineXCoord().toBigInteger().equals(r);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    static byte[] sha256(byte[] input) {
        return sha256Digest().digest(input);
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
