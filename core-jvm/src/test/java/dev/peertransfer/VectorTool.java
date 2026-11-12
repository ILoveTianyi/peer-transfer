package dev.peertransfer;

import dev.peertransfer.pairing.PairingException;
import dev.peertransfer.pairing.PairingPayload;

import java.util.Base64;

/**
 * Emits the canonical pairing vectors consumed by both the Java and the .NET test suites.
 *
 * <p>Run with {@code java -cp build/classes dev.peertransfer.VectorTool > shared/test-vectors/pairing.tsv}.
 * The values are fixed on purpose: if either implementation changes its byte layout, its suite stops
 * matching this file, which is the cross-language check.
 */
public final class VectorTool {

    private static final long NOW = 1_740_000_000L;

    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        out.append("# name\tnow_epoch_s\texpected\tbase64\n");

        PairingPayload lan = payload(PairingPayload.Mode.LAN,
                PairingPayload.FLAG_TLS | PairingPayload.FLAG_LOCALSEND, 53317,
                NOW + 300, "192.168.1.42", "Desk & Phone");
        append(out, "lan_valid", NOW, "OK", lan.encode());

        PairingPayload hotspot = payload(PairingPayload.Mode.HOTSPOT,
                PairingPayload.FLAG_TLS, 65123, NOW + 120, "192.168.49.1", "Phone");
        append(out, "hotspot_valid", NOW, "OK", hotspot.encode());

        PairingPayload pin = payload(PairingPayload.Mode.LAN,
                PairingPayload.FLAG_TLS | PairingPayload.FLAG_PIN_REQUIRED, 53317,
                NOW + 600, "fd00::42", "IPv6 peer");
        append(out, "ipv6_pin_valid", NOW, "OK", pin.encode());

        append(out, "expired", NOW + 400, "PT_E_EXPIRED", lan.encode());

        byte[] corrupted = lan.encode();
        corrupted[12] ^= 0x01;
        append(out, "crc_flip", NOW, "PT_E_CRC", corrupted);

        PairingPayload publicAddress = payload(PairingPayload.Mode.LAN,
                PairingPayload.FLAG_TLS, 53317, NOW + 300, "8.8.8.8", "hostile");
        append(out, "public_address", NOW, "PT_E_ADDRESS", publicAddress.encode());

        PairingPayload linkLocal = payload(PairingPayload.Mode.LAN,
                PairingPayload.FLAG_TLS, 53317, NOW + 300, "169.254.1.1", "hostile");
        append(out, "link_local_address", NOW, "PT_E_ADDRESS", linkLocal.encode());

        System.out.print(out);
    }

    private static PairingPayload payload(PairingPayload.Mode mode, int flags, int port, long expiry,
                                          String address, String name) {
        byte[] secret = new byte[PairingPayload.SECRET_BYTES];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (0xA0 + i);
        }
        return new PairingPayload(mode, flags, port, expiry, address, name, secret);
    }

    private static void append(StringBuilder out, String name, long now, String expected, byte[] raw) {
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        out.append(name).append('\t').append(now).append('\t').append(expected)
                .append('\t').append(base64).append('\n');
    }

    static String describeFailure(PairingException e) {
        return e.code().wire;
    }
}
