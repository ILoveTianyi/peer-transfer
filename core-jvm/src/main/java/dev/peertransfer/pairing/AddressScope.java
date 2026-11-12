package dev.peertransfer.pairing;

/**
 * Address policy for pairing payloads (PROTOCOL.md §2.2 rule 4).
 *
 * <p>A pairing payload is attacker-supplied input: anyone can print a QR code. If the address were
 * accepted as-is, scanning it would make this device open a connection to a host of the attacker's
 * choosing, from inside the local network. So only private and unique-local literals are accepted,
 * and everything else — loopback, unspecified, multicast, link-local, public — is refused.
 */
public final class AddressScope {

    private AddressScope() {
    }

    public static boolean isPrivateOrUla(String literal) {
        if (literal == null || literal.isEmpty()) {
            return false;
        }
        if (literal.indexOf(':') >= 0) {
            return isUniqueLocalV6(literal);
        }
        return isPrivateV4(literal);
    }

    static boolean isPrivateV4(String literal) {
        long value = parseV4(literal);
        if (value < 0) {
            return false;
        }
        int a = (int) ((value >> 24) & 0xFF);
        int b = (int) ((value >> 16) & 0xFF);
        if (a == 10) {
            return true;
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return true;
        }
        return a == 192 && b == 168;
    }

    /** Returns the address as a 32-bit integer, or -1 when it is not a dotted-quad with 0..255 parts. */
    static long parseV4(String literal) {
        String[] parts = literal.split("\\.", -1);
        if (parts.length != 4) {
            return -1;
        }
        long value = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return -1;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char ch = part.charAt(i);
                if (ch < '0' || ch > '9') {
                    return -1;
                }
                octet = octet * 10 + (ch - '0');
            }
            if (octet > 255) {
                return -1;
            }
            value = (value << 8) | octet;
        }
        return value;
    }

    /** Accepts only fc00::/7; rejects link-local, loopback, unspecified, multicast and global unicast. */
    static boolean isUniqueLocalV6(String literal) {
        if (literal.indexOf('%') >= 0) {
            return false; // scope ids name an interface, not a peer address
        }
        int doubleColon = literal.indexOf("::");
        if (doubleColon >= 0 && literal.indexOf("::", doubleColon + 1) >= 0) {
            return false;
        }
        String[] groups = new String[8];
        for (int i = 0; i < groups.length; i++) {
            groups[i] = "0";
        }
        if (doubleColon >= 0) {
            String head = literal.substring(0, doubleColon);
            String tail = literal.substring(doubleColon + 2);
            String[] headGroups = head.isEmpty() ? new String[0] : head.split(":");
            String[] tailGroups = tail.isEmpty() ? new String[0] : tail.split(":");
            if (headGroups.length + tailGroups.length > 8) {
                return false;
            }
            for (int i = 0; i < headGroups.length; i++) {
                groups[i] = headGroups[i];
            }
            for (int i = 0; i < tailGroups.length; i++) {
                groups[8 - tailGroups.length + i] = tailGroups[i];
            }
        } else {
            String[] rawGroups = literal.split(":", -1);
            if (rawGroups.length != 8) {
                return false;
            }
            System.arraycopy(rawGroups, 0, groups, 0, 8);
        }
        int[] values = new int[8];
        for (int i = 0; i < 8; i++) {
            if (groups[i].isEmpty() || groups[i].length() > 4) {
                return false;
            }
            try {
                values[i] = Integer.parseInt(groups[i], 16);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        int first = (values[0] >> 8) & 0xFF;
        return (first & 0xFE) == 0xFC;
    }
}
