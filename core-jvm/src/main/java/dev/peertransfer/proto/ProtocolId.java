package dev.peertransfer.proto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Protocol identifiers and the negotiation ladder of PROTOCOL.md §3.
 *
 * <p>Two peers use the highest scheme both understand, and the weakest scheme is never chosen by
 * accident: {@code http1} requires explicit consent, so a downgrade happens only because a person
 * allowed it, never because a list was shorter than expected.
 */
public enum ProtocolId {
    PT2("pt2", 2, true, true, true),
    LS22("ls2.2", 2, true, true, true),
    LS20("ls2.0", 1, true, false, true),
    HTTP1("http1", 0, false, false, true);

    private final String wire;
    private final int rank;
    private final boolean encrypted;
    private final boolean resumable;
    private final boolean wholeFileHash;

    ProtocolId(String wire, int rank, boolean encrypted, boolean resumable, boolean wholeFileHash) {
        this.wire = wire;
        this.rank = rank;
        this.encrypted = encrypted;
        this.resumable = resumable;
        this.wholeFileHash = wholeFileHash;
    }

    public String wire() {
        return wire;
    }

    public int rank() {
        return rank;
    }

    public boolean encrypted() {
        return encrypted;
    }

    public boolean resumable() {
        return resumable;
    }

    public boolean wholeFileHash() {
        return wholeFileHash;
    }

    public static ProtocolId parse(String wire) {
        for (ProtocolId id : values()) {
            if (id.wire.equals(wire)) {
                return id;
            }
        }
        return null;
    }

    /** Our own support list, highest first. This is what a peer receives from us. */
    public static List<String> ourOffers() {
        List<String> offers = new ArrayList<String>();
        for (ProtocolId id : values()) {
            offers.add(id.wire);
        }
        return Collections.unmodifiableList(offers);
    }

    /** Highest-first list used when a peer's list is not available. */
    public static List<ProtocolId> byRankDescending() {
        List<ProtocolId> ids = new ArrayList<ProtocolId>(Arrays.asList(values()));
        Collections.sort(ids, (left, right) -> Integer.compare(right.rank, left.rank));
        return ids;
    }

    @Override
    public String toString() {
        return wire;
    }
}
