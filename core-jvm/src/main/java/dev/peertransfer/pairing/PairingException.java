package dev.peertransfer.pairing;

/** Pairing failures. Codes are the stable strings of PROTOCOL.md §5. */
public final class PairingException extends Exception {

    private static final long serialVersionUID = 1L;

    public enum Code {
        CRC("PT_E_CRC"),
        EXPIRED("PT_E_EXPIRED"),
        ADDRESS("PT_E_ADDRESS");

        public final String wire;

        Code(String wire) {
            this.wire = wire;
        }
    }

    private final Code code;

    public PairingException(Code code, String message) {
        super(code.wire + ": " + message);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
