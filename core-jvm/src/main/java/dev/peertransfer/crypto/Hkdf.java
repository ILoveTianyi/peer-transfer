package dev.peertransfer.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * HKDF-SHA256 (RFC 5869). Both peers already hold the 16-byte pairing secret, so key separation is
 * the only thing needed to turn one secret into two directional keys.
 */
public final class Hkdf {

    private static final byte[] EMPTY = new byte[0];

    private Hkdf() {
    }

    public static byte[] extract(byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
            mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length <= 0 || length > 255 * 32) {
            throw new IllegalArgumentException("invalid HKDF length: " + length);
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] output = new byte[length];
            byte[] block = EMPTY;
            int offset = 0;
            for (int counter = 1; offset < length; counter++) {
                mac.reset();
                mac.update(block);
                if (info != null && info.length > 0) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                block = mac.doFinal();
                int take = Math.min(block.length, length - offset);
                System.arraycopy(block, 0, output, offset, take);
                offset += take;
            }
            return output;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Convenience for the handshake: one salt, two labelled keys. */
    public static byte[][] derivePair(byte[] secret, byte[] salt, String firstLabel, String secondLabel) {
        byte[] prk = extract(salt, secret);
        byte[] first = expand(prk, firstLabel.getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
        byte[] second = expand(prk, secondLabel.getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
        Arrays.fill(prk, (byte) 0);
        return new byte[][]{first, second};
    }
}
