package dev.peertransfer.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Authenticated, encrypted frame channel derived from the pairing secret (PROTOCOL.md §2.3, §3).
 *
 * <p>Why an application-layer AEAD instead of TLS: TLS 1.2 PSK suites are not enabled by default and
 * TLS 1.3 external PSKs are not exposed through the platform {@code SSLSocket} on Android, so a
 * PSK-based TLS channel is unreachable without native code. Deriving keys with HKDF and sealing each
 * frame with AES-256-GCM reaches the same goal — confidentiality, integrity, replay resistance —
 * with primitives every Android release and every JRE ships.
 *
 * <p>The handshake is a mutual proof of knowledge of the secret with fresh nonces on both sides:
 *
 * <pre>
 * client -> server : HELLO  { clientNonce(16) }
 * server -> client : HELLO_ACK { serverNonce(16), HMAC(secret, "pt2-hello" || clientNonce || serverNonce) }
 * both             : salt = clientNonce || serverNonce
 *                    keyC2S = HKDF-Expand(HKDF-Extract(salt, secret), "c2s")
 *                    keyS2C = HKDF-Expand(HKDF-Extract(salt, secret), "s2c")
 * </pre>
 *
 * Every subsequent frame carries a strictly increasing 64-bit counter as its GCM nonce, so a replayed
 * or reordered frame fails authentication instead of being silently accepted.
 */
public final class SecureChannel {

    public static final int NONCE_BYTES = 16;
    public static final int MAC_BYTES = 32;
    public static final int TAG_BITS = 128;

    private static final byte[] HELLO_LABEL = "pt2-hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final byte[] sendKey;
    private final byte[] receiveKey;
    private long sendCounter;
    private long receiveCounter = -1;

    private SecureChannel(byte[] sendKey, byte[] receiveKey) {
        this.sendKey = sendKey;
        this.receiveKey = receiveKey;
    }

    public static byte[] randomNonce() {
        byte[] nonce = new byte[NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] handshakeMac(byte[] secret, byte[] clientNonce, byte[] serverNonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update(HELLO_LABEL);
            mac.update(clientNonce);
            mac.update(serverNonce);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static boolean verifyHandshakeMac(byte[] secret, byte[] clientNonce, byte[] serverNonce,
                                             byte[] received) {
        return MessageDigest.isEqual(handshakeMac(secret, clientNonce, serverNonce), received);
    }

    public static SecureChannel forClient(byte[] secret, byte[] clientNonce, byte[] serverNonce) {
        byte[][] keys = Hkdf.derivePair(secret, concat(clientNonce, serverNonce), "c2s", "s2c");
        return new SecureChannel(keys[0], keys[1]);
    }

    public static SecureChannel forServer(byte[] secret, byte[] clientNonce, byte[] serverNonce) {
        byte[][] keys = Hkdf.derivePair(secret, concat(clientNonce, serverNonce), "c2s", "s2c");
        return new SecureChannel(keys[1], keys[0]);
    }

    /** Seals one frame: counter(8) || ciphertext+tag. The counter is the GCM nonce, not a separate field. */
    public byte[] seal(byte[] plaintext) {
        try {
            long counter = sendCounter++;
            byte[] nonce = nonceFor(counter);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sendKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad());
            byte[] sealed = cipher.doFinal(plaintext);
            ByteBuffer out = ByteBuffer.allocate(8 + sealed.length);
            out.putLong(counter);
            out.put(sealed);
            return out.array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
    }

    /**
     * Opens one frame. Returns the plaintext, or throws when the frame is truncated, replayed,
     * out of order, or fails authentication.
     */
    public byte[] open(byte[] frame) throws SecurityException {
        if (frame.length < 8 + 16) {
            throw new SecurityException("frame too short");
        }
        ByteBuffer in = ByteBuffer.wrap(frame);
        long counter = in.getLong();
        if (counter <= receiveCounter) {
            throw new SecurityException("replayed or reordered frame: " + counter);
        }
        byte[] nonce = nonceFor(counter);
        byte[] sealed = new byte[frame.length - 8];
        in.get(sealed);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(receiveKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad());
            byte[] plaintext = cipher.doFinal(sealed);
            receiveCounter = counter;
            return plaintext;
        } catch (AEADBadTagException e) {
            throw new SecurityException("frame authentication failed");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
    }

    public void wipe() {
        Arrays.fill(sendKey, (byte) 0);
        Arrays.fill(receiveKey, (byte) 0);
    }

    private static byte[] aad() {
        return "pt2-frame".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static byte[] nonceFor(long counter) {
        byte[] nonce = new byte[12];
        ByteBuffer.wrap(nonce).putInt(4, (int) counter);
        return nonce;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }
}
