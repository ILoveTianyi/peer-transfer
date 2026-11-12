package dev.peertransfer.net;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Wi-Fi strategy and restoration contract (docs/NETWORK.md).
 *
 * <p>Two things are decided here, both before a single socket is opened:
 *
 * <ol>
 *   <li>whether the transfer link can coexist with the user's normal internet connection;</li>
 *   <li>exactly what has to be put back when the transfer ends.</li>
 * </ol>
 *
 * <p>Concurrency is treated optimistically on purpose. Modern SoCs (Snapdragon 8 Elite class and most
 * recent flagships) run station and access-point roles at the same time, and a hotspot can often be
 * tethered to the current upstream. So an unknown capability attempts the internet-preserving path and
 * verifies it, instead of refusing up front; only an explicit "cannot do both" turns into a consent
 * question.
 */
public final class NetworkPlan {

    public enum LinkKind {
        SAME_LAN,
        WIFI_DIRECT,
        HOTSPOT_HOSTED,
        HOTSPOT_JOINED
    }

    /** What the platform reported, or {@link #UNKNOWN} when nothing was queried yet. */
    public enum Concurrency {
        SUPPORTED,
        UNSUPPORTED,
        UNKNOWN
    }

    public enum Strategy {
        /** Leave the current network alone; the peer is reachable on it. */
        USE_EXISTING_NETWORK,
        /** Take a secondary/hidden link; the internet connection stays usable. */
        SECONDARY_LINK_KEEP_INTERNET,
        /** Publish a private link that keeps internet by sharing the current upstream. */
        PRIVATE_LINK_WITH_INTERNET,
        /** Attempt the internet-preserving path; the caller must verify it and report the outcome. */
        ATTEMPT_SECONDARY_LINK_KEEP_INTERNET,
        /** Host or join a private link; internet on this device may pause. Needs consent. */
        PRIVATE_LINK_MAY_PAUSE_INTERNET,
        /** Refuse: the user demanded internet, the device cannot do both, consent was not given. */
        REFUSE_WOULD_DROP_INTERNET
    }

    public static final class Snapshot {
        private final boolean wifiEnabled;
        private final String connectedSsid;
        private final Integer connectedNetworkId;
        private final boolean airplaneMode;

        public Snapshot(boolean wifiEnabled, String connectedSsid, Integer connectedNetworkId,
                        boolean airplaneMode) {
            this.wifiEnabled = wifiEnabled;
            this.connectedSsid = connectedSsid == null ? "" : connectedSsid;
            this.connectedNetworkId = connectedNetworkId;
            this.airplaneMode = airplaneMode;
        }

        public boolean wifiEnabled() {
            return wifiEnabled;
        }

        public String connectedSsid() {
            return connectedSsid;
        }

        public Integer connectedNetworkId() {
            return connectedNetworkId;
        }

        public boolean airplaneMode() {
            return airplaneMode;
        }

        @Override
        public String toString() {
            return "Snapshot{wifiEnabled=" + wifiEnabled + ", ssid='" + connectedSsid
                    + "', netId=" + connectedNetworkId + ", airplaneMode=" + airplaneMode + "}";
        }
    }

    public enum RestoreAction {
        REENABLE_WIFI,
        RECONNECT_PREVIOUS_NETWORK,
        WAIT_FOR_INTERNET_VALIDATION,
        RESTORE_AIRPLANE_MODE
    }

    public static final class Decision {
        private final Strategy strategy;
        private final String warning;

        Decision(Strategy strategy, String warning) {
            this.strategy = strategy;
            this.warning = warning;
        }

        public Strategy strategy() {
            return strategy;
        }

        public String warning() {
            return warning;
        }

        public boolean refused() {
            return strategy == Strategy.REFUSE_WOULD_DROP_INTERNET;
        }

        /**
         * True when the chosen strategy assumes a capability that was not proven: the caller must
         * observe whether the primary network stays validated and report the result, rather than
         * trusting the assumption.
         */
        public boolean verifyAtRuntime() {
            return strategy == Strategy.ATTEMPT_SECONDARY_LINK_KEEP_INTERNET;
        }

        @Override
        public String toString() {
            return strategy + (warning.isEmpty() ? "" : " (" + warning + ")");
        }
    }

    private NetworkPlan() {
    }

    /** Convenience overload for the common case: the capability was not queried. */
    public static Decision decide(boolean concurrentNetworksSupported, boolean internetMustStay,
                                  LinkKind linkKind, boolean consentToPauseInternet) {
        return decide(concurrentNetworksSupported ? Concurrency.SUPPORTED : Concurrency.UNSUPPORTED,
                internetMustStay, linkKind, consentToPauseInternet, false);
    }

    /**
     * @param concurrency            what the platform reported about simultaneous station + AP roles
     * @param internetMustStay       the user asked to keep the normal internet connection
     * @param linkKind               the kind of link that would be used
     * @param consentToPauseInternet the user accepted a temporary loss of internet
     * @param canShareUpstream       the hotspot can use the current connection as its upstream, so
     *                               internet survives for this device and for the peer
     */
    public static Decision decide(Concurrency concurrency, boolean internetMustStay,
                                  LinkKind linkKind, boolean consentToPauseInternet,
                                  boolean canShareUpstream) {
        if (linkKind == LinkKind.SAME_LAN) {
            return new Decision(Strategy.USE_EXISTING_NETWORK, "");
        }
        if (linkKind == LinkKind.HOTSPOT_HOSTED && canShareUpstream) {
            // Tethering the current upstream keeps internet on this device and gives the peer a route.
            return new Decision(Strategy.PRIVATE_LINK_WITH_INTERNET, "");
        }
        if (concurrency == Concurrency.SUPPORTED) {
            return new Decision(Strategy.SECONDARY_LINK_KEEP_INTERNET, "");
        }
        if (concurrency == Concurrency.UNKNOWN) {
            // Optimistic: try it, verify with ConnectivityManager, fall back only if it fails.
            return new Decision(Strategy.ATTEMPT_SECONDARY_LINK_KEEP_INTERNET,
                    "concurrency not yet verified; confirming internet stays up");
        }
        if (!internetMustStay) {
            return new Decision(Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET, "");
        }
        if (consentToPauseInternet) {
            return new Decision(Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET,
                    "internet will pause during the transfer on this device");
        }
        return new Decision(Strategy.REFUSE_WOULD_DROP_INTERNET,
                "this device reports no simultaneous station + AP support for " + linkKind
                        + "; ask the user before pausing the internet connection");
    }

    /**
     * Outcome of the runtime verification for {@link Strategy#ATTEMPT_SECONDARY_LINK_KEEP_INTERNET}.
     * Returns the strategy to continue with once the primary network was or was not kept validated.
     */
    public static Decision afterVerification(Decision attempted, boolean internetStayedValidated,
                                             boolean internetMustStay, boolean consentToPauseInternet) {
        if (attempted.strategy() != Strategy.ATTEMPT_SECONDARY_LINK_KEEP_INTERNET) {
            return attempted;
        }
        if (internetStayedValidated) {
            return new Decision(Strategy.SECONDARY_LINK_KEEP_INTERNET, "");
        }
        if (!internetMustStay || consentToPauseInternet) {
            return new Decision(Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET,
                    "internet dropped during link setup");
        }
        return new Decision(Strategy.REFUSE_WOULD_DROP_INTERNET,
                "link setup dropped the internet connection; restore it and ask the user");
    }

    /**
     * What must be undone, in order. The list is derived from the difference between the snapshot and
     * the state after teardown, so an unchanged field produces no action and a restore that would be a
     * no-op is not reported as one.
     */
    public static List<RestoreAction> restoreSteps(Snapshot before, boolean wifiEnabledAfter,
                                                   boolean onPreviousNetworkAfter) {
        List<RestoreAction> steps = new ArrayList<RestoreAction>();
        if (before == null) {
            return Collections.unmodifiableList(steps);
        }
        if (before.wifiEnabled() && !wifiEnabledAfter) {
            steps.add(RestoreAction.REENABLE_WIFI);
        }
        if (before.wifiEnabled() && !onPreviousNetworkAfter
                && (before.connectedNetworkId() != null || !before.connectedSsid().isEmpty())) {
            steps.add(RestoreAction.RECONNECT_PREVIOUS_NETWORK);
        }
        if (!steps.isEmpty()) {
            steps.add(RestoreAction.WAIT_FOR_INTERNET_VALIDATION);
        }
        return Collections.unmodifiableList(steps);
    }

    /** True when the snapshot claims a connection that the restore steps would have to recreate. */
    public static boolean hadUsableConnection(Snapshot snapshot) {
        return snapshot != null && snapshot.wifiEnabled()
                && (snapshot.connectedNetworkId() != null || !snapshot.connectedSsid().isEmpty());
    }
}
