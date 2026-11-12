package dev.peertransfer.pairing;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * The pairing payload of PROTOCOL.md §2. One payload travels over QR, Bluetooth LE and NFC; only the
 * carrier differs, so a peer that scanned a QR and a peer that tapped NFC pair identically.
 *
 * <p>Decoding enforces every rule in §2.2 as a hard failure. In particular the address must be a
 * private/ULA literal: a payload that points anywhere else is refused before any socket is opened.
 */
public final class PairingPayload {

    public static final int PAYLOAD_VERSION = 1;
    public static final int SECRET_BYTES = 16;
    public static final int MAX_ADDRESS_BYTES = 45;
    public static final int MAX_NAME_BYTES = 64;
    public static final int MAX_TTL_SECONDS = 600;

    private static final int MAGIC_0 = 0x50;
    private static final int MAGIC_1 = 0x54;
    private static final int FIXED_PREFIX = 11;
    private static final int FIXED_SUFFIX = SECRET_BYTES + 2;

    public enum Mode {
        LAN(1),
        HOTSPOT(2);

        public final int wire;

        Mode(int wire) {
            this.wire = wire;
        }

        static Mode fromWire(int value) throws PairingException {
            for (Mode mode : values()) {
                if (mode.wire == value) {
                    return mode;
                }
            }
            throw new PairingException(PairingException.Code.EXPIRED, "unknown mode " + value);
        }
    }

    /** Flags that let a peer decide what it may negotiate before connecting (PROTOCOL.md §2.1). */
    public static final int FLAG_TLS = 1;
    public static final int FLAG_LOCALSEND = 1 << 1;
    public static final int FLAG_PIN_REQUIRED = 1 << 2;

    private final Mode mode;
    private final int flags;
    private final int port;
    private final long expiresAtEpochSeconds;
    private final String address;
    private final String displayName;
    private final byte[] secret;

    public PairingPayload(Mode mode, int flags, int port, long expiresAtEpochSeconds,
                          String address, String displayName, byte[] secret) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
        if (secret == null || secret.length != SECRET_BYTES) {
            throw new IllegalArgumentException("secret must be " + SECRET_BYTES + " bytes");
        }
        this.mode = mode;
        this.flags = flags & 0xFF;
        this.port = port;
        this.expiresAtEpochSeconds = expiresAtEpochSeconds;
        this.address = address;
        this.displayName = displayName == null ? "" : displayName;
        this.secret = secret.clone();
    }

    public Mode mode() {
        return mode;
    }

    public int flags() {
        return flags;
    }

    public int port() {
        return port;
    }

    public long expiresAtEpochSeconds() {
        return expiresAtEpochSeconds;
    }

    public String address() {
        return address;
    }

    public String displayName() {
        return displayName;
    }

    public byte[] secret() {
        return secret.clone();
    }

    public boolean acceptsTls() {
        return (flags & FLAG_TLS) != 0;
    }

    public boolean speaksLocalSend() {
        return (flags & FLAG_LOCALSEND) != 0;
    }

    public boolean pinRequired() {
        return (flags & FLAG_PIN_REQUIRED) != 0;
    }

    /** Encodes to the raw payload bytes (see {@link #encodeBase64()} for the QR form). */
    public byte[] encode() {
        byte[] addressBytes = address.getBytes(StandardCharsets.UTF_8);
        byte[] nameBytes = displayName.getBytes(StandardCharsets.UTF_8);
        if (addressBytes.length < 1 || addressBytes.length > MAX_ADDRESS_BYTES) {
            throw new IllegalStateException("address length " + addressBytes.length + " not encodable");
        }
        if (nameBytes.length > MAX_NAME_BYTES) {
            throw new IllegalStateException("name length " + nameBytes.length + " exceeds 64 bytes");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(FIXED_PREFIX + addressBytes.length
                + 1 + nameBytes.length + FIXED_SUFFIX);
        out.write(MAGIC_0);
        out.write(MAGIC_1);
        out.write(PAYLOAD_VERSION);
        out.write(mode.wire);
        out.write(flags);
        out.write((port >>> 8) & 0xFF);
        out.write(port & 0xFF);
        writeInt(out, expiresAtEpochSeconds);
        out.write(addressBytes.length);
        out.write(addressBytes, 0, addressBytes.length);
        out.write(nameBytes.length);
        out.write(nameBytes, 0, nameBytes.length);
        out.write(secret, 0, secret.length);
        byte[] withoutCrc = out.toByteArray();
        int crc = Crc16.compute(withoutCrc, 0, withoutCrc.length);
        out.write((crc >>> 8) & 0xFF);
        out.write(crc & 0xFF);
        return out.toByteArray();
    }

    public String encodeBase64() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode());
    }

    /** QR form: base64url without padding, validated against the wall clock. */
    public static PairingPayload decodeBase64(String text) throws PairingException {
        return decodeBase64(text, System.currentTimeMillis() / 1000L);
    }

    /** QR form with an explicit clock, so the expiry rule is testable without waiting. */
    public static PairingPayload decodeBase64(String text, long nowEpochSeconds)
            throws PairingException {
        byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(text.trim());
        } catch (IllegalArgumentException e) {
            throw new PairingException(PairingException.Code.CRC, "payload is not valid base64url");
        }
        return decode(raw, nowEpochSeconds);
    }

    public static PairingPayload decode(byte[] raw, long nowEpochSeconds) throws PairingException {
        if (raw.length < FIXED_PREFIX + 1 + 1 + FIXED_SUFFIX) {
            throw new PairingException(PairingException.Code.CRC, "payload too short: " + raw.length);
        }
        if ((raw[0] & 0xFF) != MAGIC_0 || (raw[1] & 0xFF) != MAGIC_1) {
            throw new PairingException(PairingException.Code.CRC, "bad magic");
        }
        int bodyLength = raw.length - 2;
        int expectedCrc = ((raw[bodyLength] & 0xFF) << 8) | (raw[bodyLength + 1] & 0xFF);
        int actualCrc = Crc16.compute(raw, 0, bodyLength);
        if (expectedCrc != actualCrc) {
            throw new PairingException(PairingException.Code.CRC, "crc mismatch");
        }
        int version = raw[2] & 0xFF;
        if (version != PAYLOAD_VERSION) {
            throw new PairingException(PairingException.Code.CRC, "unsupported payload version " + version);
        }
        Mode mode = Mode.fromWire(raw[3] & 0xFF);
        int flags = raw[4] & 0xFF;
        int port = ((raw[5] & 0xFF) << 8) | (raw[6] & 0xFF);
        long expiry = readInt(raw, 7);
        int cursor = FIXED_PREFIX;
        int addressLength = raw[cursor++] & 0xFF;
        if (addressLength < 1 || addressLength > MAX_ADDRESS_BYTES
                || cursor + addressLength + 1 > bodyLength) {
            throw new PairingException(PairingException.Code.CRC, "address length invalid");
        }
        String address = new String(raw, cursor, addressLength, StandardCharsets.UTF_8);
        cursor += addressLength;
        int nameLength = raw[cursor++] & 0xFF;
        if (nameLength > MAX_NAME_BYTES || cursor + nameLength + SECRET_BYTES > bodyLength) {
            throw new PairingException(PairingException.Code.CRC, "name length invalid");
        }
        String name = new String(raw, cursor, nameLength, StandardCharsets.UTF_8);
        cursor += nameLength;
        byte[] secret = Arrays.copyOfRange(raw, cursor, cursor + SECRET_BYTES);
        if (nowEpochSeconds >= expiry) {
            throw new PairingException(PairingException.Code.EXPIRED,
                    "payload expired at " + expiry + ", now " + nowEpochSeconds);
        }
        if (!AddressScope.isPrivateOrUla(address)) {
            throw new PairingException(PairingException.Code.ADDRESS,
                    "refusing non-private peer address: " + address);
        }
        return new PairingPayload(mode, flags, port, expiry, address, name, secret);
    }

    private static void writeInt(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    private static long readInt(byte[] raw, int offset) {
        return ((long) (raw[offset] & 0xFF) << 24)
                | ((long) (raw[offset + 1] & 0xFF) << 16)
                | ((long) (raw[offset + 2] & 0xFF) << 8)
                | (raw[offset + 3] & 0xFF);
    }

    @Override
    public String toString() {
        return "PairingPayload{" + mode + ", port=" + port + ", address=" + address
                + ", name='" + displayName + "', tls=" + acceptsTls() + "}";
    }
}
