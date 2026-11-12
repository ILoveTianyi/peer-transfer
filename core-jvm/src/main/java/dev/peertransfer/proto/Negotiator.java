package dev.peertransfer.proto;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

/** Chooses the protocol for a session, per PROTOCOL.md §3. */
public final class Negotiator {

    public enum ErrorCode {
        OK("PT_OK"),
        NO_COMMON_PROTOCOL("PT_E_NO_COMMON_PROTOCOL"),
        INSECURE_ONLY("PT_E_INSECURE_ONLY");

        public final String wire;

        ErrorCode(String wire) {
            this.wire = wire;
        }
    }

    public static final class Result {
        private final ErrorCode code;
        private final ProtocolId chosen;
        private final String detail;

        private Result(ErrorCode code, ProtocolId chosen, String detail) {
            this.code = code;
            this.chosen = chosen;
            this.detail = detail;
        }

        public ErrorCode code() {
            return code;
        }

        public ProtocolId chosen() {
            return chosen;
        }

        public String detail() {
            return detail;
        }

        public boolean ok() {
            return code == ErrorCode.OK;
        }

        @Override
        public String toString() {
            return ok() ? ("OK " + chosen.wire()) : (code.wire + ": " + detail);
        }
    }

    private Negotiator() {
    }

    /**
     * @param peerOffers the peer's ordered list, highest first; unknown identifiers are ignored
     * @param plaintextConsented whether the user allowed {@code http1} for this session
     */
    public static Result choose(List<String> peerOffers, boolean plaintextConsented) {
        EnumSet<ProtocolId> accepted = EnumSet.noneOf(ProtocolId.class);
        List<String> unknown = new ArrayList<String>();
        for (String offer : peerOffers) {
            ProtocolId id = ProtocolId.parse(offer);
            if (id == null) {
                unknown.add(offer);
            } else {
                accepted.add(id);
            }
        }
        for (ProtocolId candidate : ProtocolId.byRankDescending()) {
            if (!accepted.contains(candidate)) {
                continue;
            }
            if (candidate == ProtocolId.HTTP1 && !plaintextConsented) {
                return new Result(ErrorCode.INSECURE_ONLY, null,
                        "peer offers only plaintext transfer; user consent required");
            }
            return new Result(ErrorCode.OK, candidate, "");
        }
        return new Result(ErrorCode.NO_COMMON_PROTOCOL, null,
                "no common protocol; peer=" + describe(peerOffers) + " unknown=" + unknown);
    }

    private static String describe(Collection<String> offers) {
        StringBuilder builder = new StringBuilder("[");
        boolean first = true;
        for (String offer : offers) {
            if (!first) {
                builder.append(',');
            }
            builder.append(offer);
            first = false;
        }
        return builder.append(']').toString();
    }
}
