package dev.peertransfer;

import dev.peertransfer.net.NetworkPlan;
import dev.peertransfer.pairing.AddressScope;
import dev.peertransfer.pairing.PairingException;
import dev.peertransfer.pairing.PairingPayload;
import dev.peertransfer.proto.Negotiator;
import dev.peertransfer.proto.ProtocolId;
import dev.peertransfer.transfer.ChunkPlan;
import dev.peertransfer.transfer.TransferState;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Assertion suite for the Android-free core. No third-party test framework: the build script runs
 * this class with plain {@code java}, which is what makes the core verifiable without Gradle, a
 * device, or network access.
 */
public final class CoreTests {

    private static int checks;
    private static final List<String> failures = new ArrayList<String>();

    public static void main(String[] args) {
        pairingRoundTrip();
        pairingTamperDetection();
        pairingRejectsNonPrivateAddresses();
        addressScopeRules();
        negotiationChoosesHighestCommon();
        negotiationRefusesSilentPlaintext();
        negotiationHandlesUnknownAndDisjoint();
        chunkPlanArithmetic();
        chunkResumeBoundaries();
        transferStateMachine();
        networkStrategy();
        networkRestore();

        System.out.println("CHECKS: " + checks + " run, " + failures.size() + " failed");
        for (String failure : failures) {
            System.out.println("FAILED: " + failure);
        }
        if (!failures.isEmpty()) {
            System.exit(1);
        }
        System.out.println("tests OK");
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
        }
    }

    private static void checkEquals(String what, Object expected, Object actual) {
        checks++;
        boolean equal = expected == null ? actual == null : expected.equals(actual);
        if (!equal) {
            failures.add(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static PairingPayload sample(long expiry) {
        byte[] secret = new byte[PairingPayload.SECRET_BYTES];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (i * 7 + 1);
        }
        return new PairingPayload(PairingPayload.Mode.LAN,
                PairingPayload.FLAG_TLS | PairingPayload.FLAG_LOCALSEND, 53317, expiry,
                "192.168.1.42", "Desk & Phone", secret);
    }

    private static void pairingRoundTrip() {
        long now = System.currentTimeMillis() / 1000L;
        long expiry = now + 300;
        PairingPayload original = sample(expiry);
        byte[] encoded = original.encode();
        check("payload length under 128 bytes", encoded.length < 128);
        try {
            PairingPayload decoded = PairingPayload.decode(encoded, now);
            checkEquals("mode", original.mode(), decoded.mode());
            checkEquals("port", original.port(), decoded.port());
            checkEquals("address", original.address(), decoded.address());
            checkEquals("name", original.displayName(), decoded.displayName());
            checkEquals("tls flag", true, decoded.acceptsTls());
            checkEquals("localsend flag", true, decoded.speaksLocalSend());
            check("payload not pin required", !decoded.pinRequired());

            String qr = original.encodeBase64();
            check("base64 payload has no padding", qr.indexOf('=') < 0);
            PairingPayload fromQr = PairingPayload.decodeBase64(qr, now);
            checkEquals("qr round trip address", original.address(), fromQr.address());
        } catch (PairingException e) {
            check("payload round trip threw " + e.getMessage(), false);
        }
    }

    private static void pairingTamperDetection() {
        long now = System.currentTimeMillis() / 1000L;
        long expiry = now + 300;
        byte[] encoded = sample(expiry).encode();
        byte[] corrupted = encoded.clone();
        corrupted[12] ^= 0x01; // flip a bit inside the address
        try {
            PairingPayload.decode(corrupted, now);
            check("corrupted payload must be rejected", false);
        } catch (PairingException e) {
            checkEquals("corruption code", PairingException.Code.CRC, e.code());
        }

        try {
            PairingPayload.decode(encoded, expiry);
            check("expired payload must be rejected", false);
        } catch (PairingException e) {
            checkEquals("expiry code", PairingException.Code.EXPIRED, e.code());
        }

        try {
            PairingPayload.decodeBase64("not base64 !!", now);
            check("garbage base64 must be rejected", false);
        } catch (PairingException e) {
            checkEquals("garbage code", PairingException.Code.CRC, e.code());
        }
    }

    private static void pairingRejectsNonPrivateAddresses() {
        long now = System.currentTimeMillis() / 1000L;
        long expiry = now + 300;
        String[] hostile = {"8.8.8.8", "127.0.0.1", "0.0.0.0", "239.1.1.1", "169.254.1.1",
                "fe80::1", "::1", "2001:4860:4860::8888", "192.168.1.1%wlan0", "192.168.1.999"};
        for (String address : hostile) {
            try {
                PairingPayload payload = new PairingPayload(PairingPayload.Mode.LAN,
                        PairingPayload.FLAG_TLS, 53317, expiry, address, "x",
                        new byte[PairingPayload.SECRET_BYTES]);
                PairingPayload.decode(payload.encode(), now);
                check("hostile address must be refused: " + address, false);
            } catch (PairingException e) {
                checkEquals("hostile address code for " + address,
                        PairingException.Code.ADDRESS, e.code());
            }
        }
    }

    private static void addressScopeRules() {
        check("10.0.0.5 private", AddressScope.isPrivateOrUla("10.0.0.5"));
        check("172.16.5.1 private", AddressScope.isPrivateOrUla("172.16.5.1"));
        check("172.31.255.254 private", AddressScope.isPrivateOrUla("172.31.255.254"));
        check("172.32.0.1 not private", !AddressScope.isPrivateOrUla("172.32.0.1"));
        check("192.168.43.1 private", AddressScope.isPrivateOrUla("192.168.43.1"));
        check("fd00::1 ula", AddressScope.isPrivateOrUla("fd00::1"));
        check("fc00::1 ula", AddressScope.isPrivateOrUla("fc00::1"));
        check("fe80::1 link-local refused", !AddressScope.isPrivateOrUla("fe80::1"));
        check("empty refused", !AddressScope.isPrivateOrUla(""));
    }

    private static void negotiationChoosesHighestCommon() {
        List<String> peer = Arrays.asList("ls2.2", "pt2", "http1");
        Negotiator.Result result = Negotiator.choose(peer, false);
        check("negotiation ok", result.ok());
        checkEquals("highest common", ProtocolId.PT2, result.chosen());

        Negotiator.Result withoutPt2 = Negotiator.choose(Arrays.asList("ls2.2", "ls2.0"), false);
        checkEquals("falls to ls2.2", ProtocolId.LS22, withoutPt2.chosen());

        Negotiator.Result ls20 = Negotiator.choose(Arrays.asList("ls2.0"), false);
        checkEquals("falls to ls2.0", ProtocolId.LS20, ls20.chosen());
        check("ls2.0 not resumable", !ProtocolId.LS20.resumable());
        check("ls2.2 resumable", ProtocolId.LS22.resumable());
        check("pt2 encrypted", ProtocolId.PT2.encrypted());
    }

    private static void negotiationRefusesSilentPlaintext() {
        Negotiator.Result refused = Negotiator.choose(Arrays.asList("http1"), false);
        check("plaintext-only must fail", !refused.ok());
        checkEquals("plaintext refusal code",
                Negotiator.ErrorCode.INSECURE_ONLY, refused.code());

        Negotiator.Result consented = Negotiator.choose(Arrays.asList("http1"), true);
        check("consented plaintext allowed", consented.ok());
        checkEquals("consented choice", ProtocolId.HTTP1, consented.chosen());

        Negotiator.Result mixed = Negotiator.choose(Arrays.asList("http1", "ls2.2"), false);
        check("secure option wins over plaintext", mixed.chosen() == ProtocolId.LS22);
    }

    private static void negotiationHandlesUnknownAndDisjoint() {
        Negotiator.Result unknown = Negotiator.choose(Arrays.asList("future-3", "pt2"), false);
        check("unknown identifier ignored", unknown.ok() && unknown.chosen() == ProtocolId.PT2);

        Negotiator.Result disjoint = Negotiator.choose(Arrays.asList("future-3"), false);
        check("disjoint lists fail", !disjoint.ok());
        checkEquals("disjoint code",
                Negotiator.ErrorCode.NO_COMMON_PROTOCOL, disjoint.code());
        check("disjoint detail names the peer list",
                disjoint.detail().contains("future-3"));
    }

    private static void chunkPlanArithmetic() {
        ChunkPlan one = new ChunkPlan(1);
        checkEquals("one-byte file has one chunk", 1, one.chunkCount());
        checkEquals("one-byte chunk length", 1, one.chunk(0).length());

        ChunkPlan exact = new ChunkPlan(2L * ChunkPlan.DEFAULT_CHUNK_BYTES);
        checkEquals("exact multiple count", 2, exact.chunkCount());
        checkEquals("second chunk length", ChunkPlan.DEFAULT_CHUNK_BYTES, exact.chunk(1).length());

        ChunkPlan ragged = new ChunkPlan(2L * ChunkPlan.DEFAULT_CHUNK_BYTES + 5);
        checkEquals("ragged count", 3, ragged.chunkCount());
        checkEquals("ragged last length", 5, ragged.chunk(2).length());
        checkEquals("ragged last offset", 2L * ChunkPlan.DEFAULT_CHUNK_BYTES, ragged.chunk(2).offset());

        checkEquals("empty file has no chunks", 0, new ChunkPlan(0).chunkCount());
        checkEquals("empty file resume is complete", 0, new ChunkPlan(0).resumeIndex(0));

        ChunkPlan small = new ChunkPlan(2500, 1000);
        checkEquals("small chunk count", 3, small.chunkCount());
        checkEquals("small chunk 1 offset", 1000L, small.chunk(1).offset());
        checkEquals("small chunk 2 length", 500, small.chunk(2).length());
        checkEquals("all() size", 3, small.all().size());
    }

    private static void chunkResumeBoundaries() {
        ChunkPlan plan = new ChunkPlan(3500, 1000);
        checkEquals("resume at zero", 0, plan.resumeIndex(0));
        checkEquals("resume mid chunk rounds down", 0, plan.resumeIndex(999));
        checkEquals("resume on boundary", 1, plan.resumeIndex(1000));
        checkEquals("resume after two chunks", 2, plan.resumeIndex(2000));
        checkEquals("resume at file size", 4, plan.resumeIndex(3500));
        checkEquals("resume beyond file size", 4, plan.resumeIndex(9000));
        checkEquals("remaining after 1000 bytes", 3, plan.remaining(1000).size());
        checkEquals("remaining chunk index", 1, plan.remaining(1000).get(0).index());
        try {
            plan.resumeIndex(-1);
            check("negative verified bytes must throw", false);
        } catch (IllegalArgumentException e) {
            check("negative verified bytes threw", true);
        }
    }

    private static void transferStateMachine() {
        TransferState state = new TransferState();
        checkEquals("initial state", TransferState.State.IDLE, state.state());
        state.paired();
        state.negotiated();
        state.preparing();
        state.sending();
        state.verifying();
        state.done();
        check("done is terminal", state.terminal());
        checkEquals("final state", TransferState.State.DONE, state.state());

        TransferState illegal = new TransferState();
        try {
            illegal.sending();
            check("sending before pairing must throw", false);
        } catch (IllegalStateException e) {
            check("illegal transition threw", true);
        }

        TransferState cancelled = new TransferState();
        cancelled.paired();
        cancelled.cancel();
        check("cancelled is terminal", cancelled.terminal());
        cancelled.cancel();
        checkEquals("idempotent cancel keeps state", TransferState.State.CANCELLED, cancelled.state());
        try {
            cancelled.sending();
            check("sending after cancel must throw", false);
        } catch (IllegalStateException e) {
            check("sending after cancel threw", true);
        }

        TransferState failed = new TransferState();
        failed.paired();
        failed.fail();
        checkEquals("failed state", TransferState.State.FAILED, failed.state());
        try {
            failed.done();
            check("done after failure must throw", false);
        } catch (IllegalStateException e) {
            check("done after failure threw", true);
        }
    }

    private static void networkStrategy() {
        NetworkPlan.Decision sameLan = NetworkPlan.decide(false, true,
                NetworkPlan.LinkKind.SAME_LAN, false);
        checkEquals("same lan keeps existing network",
                NetworkPlan.Strategy.USE_EXISTING_NETWORK, sameLan.strategy());

        NetworkPlan.Decision concurrent = NetworkPlan.decide(true, true,
                NetworkPlan.LinkKind.WIFI_DIRECT, false);
        checkEquals("concurrent link keeps internet",
                NetworkPlan.Strategy.SECONDARY_LINK_KEEP_INTERNET, concurrent.strategy());
        check("concurrent decision has no warning", concurrent.warning().isEmpty());
        check("concurrent decision needs no verification", !concurrent.verifyAtRuntime());

        // Modern hardware: STA+AP concurrency, so an unqueried capability is attempted, not refused.
        NetworkPlan.Decision unknown = NetworkPlan.decide(NetworkPlan.Concurrency.UNKNOWN, true,
                NetworkPlan.LinkKind.HOTSPOT_HOSTED, false, false);
        checkEquals("unknown concurrency attempts to keep internet",
                NetworkPlan.Strategy.ATTEMPT_SECONDARY_LINK_KEEP_INTERNET, unknown.strategy());
        check("unknown concurrency asks for runtime verification", unknown.verifyAtRuntime());
        check("unknown concurrency is not a refusal", !unknown.refused());

        NetworkPlan.Decision shared = NetworkPlan.decide(NetworkPlan.Concurrency.UNSUPPORTED, true,
                NetworkPlan.LinkKind.HOTSPOT_HOSTED, false, true);
        checkEquals("tethered hotspot keeps internet",
                NetworkPlan.Strategy.PRIVATE_LINK_WITH_INTERNET, shared.strategy());

        NetworkPlan.Decision pause = NetworkPlan.decide(
                NetworkPlan.Concurrency.UNSUPPORTED, false,
                NetworkPlan.LinkKind.HOTSPOT_HOSTED, false, false);
        checkEquals("pausing allowed when user did not demand internet",
                NetworkPlan.Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET, pause.strategy());

        NetworkPlan.Decision refused = NetworkPlan.decide(
                NetworkPlan.Concurrency.UNSUPPORTED, true,
                NetworkPlan.LinkKind.HOTSPOT_HOSTED, false, false);
        check("refuses only when capability is explicitly absent", refused.refused());
        check("refusal explains why", refused.warning().contains("no simultaneous station + AP"));

        NetworkPlan.Decision consented = NetworkPlan.decide(
                NetworkPlan.Concurrency.UNSUPPORTED, true,
                NetworkPlan.LinkKind.HOTSPOT_HOSTED, true, false);
        checkEquals("consent allows pause",
                NetworkPlan.Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET, consented.strategy());
        check("consent still warns", consented.warning().contains("internet will pause"));

        // Verification outcomes for the optimistic path.
        NetworkPlan.Decision verifiedOk = NetworkPlan.afterVerification(unknown, true, true, false);
        checkEquals("verified internet stays up",
                NetworkPlan.Strategy.SECONDARY_LINK_KEEP_INTERNET, verifiedOk.strategy());
        NetworkPlan.Decision verifiedDropped = NetworkPlan.afterVerification(unknown, false, true, false);
        check("dropped internet without consent refuses", verifiedDropped.refused());
        NetworkPlan.Decision verifiedDroppedConsented =
                NetworkPlan.afterVerification(unknown, false, true, true);
        checkEquals("dropped internet with consent continues",
                NetworkPlan.Strategy.PRIVATE_LINK_MAY_PAUSE_INTERNET,
                verifiedDroppedConsented.strategy());
        NetworkPlan.Decision notAttempted = NetworkPlan.afterVerification(concurrent, false, true, false);
        checkEquals("verification is a no-op for settled strategies",
                NetworkPlan.Strategy.SECONDARY_LINK_KEEP_INTERNET, notAttempted.strategy());
    }

    private static void networkRestore() {
        NetworkPlan.Snapshot home = new NetworkPlan.Snapshot(true, "Home", 42, false);
        check("snapshot had usable connection", NetworkPlan.hadUsableConnection(home));

        List<NetworkPlan.RestoreAction> full = NetworkPlan.restoreSteps(home, false, false);
        checkEquals("restore has three steps", 3, full.size());
        checkEquals("reenable first", NetworkPlan.RestoreAction.REENABLE_WIFI, full.get(0));
        checkEquals("reconnect second",
                NetworkPlan.RestoreAction.RECONNECT_PREVIOUS_NETWORK, full.get(1));
        checkEquals("validate internet last",
                NetworkPlan.RestoreAction.WAIT_FOR_INTERNET_VALIDATION, full.get(2));

        List<NetworkPlan.RestoreAction> wifiStayed = NetworkPlan.restoreSteps(home, true, false);
        checkEquals("wifi kept: reconnect only plus validate", 2, wifiStayed.size());
        checkEquals("wifi kept: no reenable",
                NetworkPlan.RestoreAction.RECONNECT_PREVIOUS_NETWORK, wifiStayed.get(0));

        List<NetworkPlan.RestoreAction> unchanged = NetworkPlan.restoreSteps(home, true, true);
        check("nothing to restore when state matches", unchanged.isEmpty());

        NetworkPlan.Snapshot wifiOff = new NetworkPlan.Snapshot(false, "", null, false);
        check("wifi-off snapshot has no usable connection",
                !NetworkPlan.hadUsableConnection(wifiOff));
        check("wifi-off snapshot requires no re-enable",
                NetworkPlan.restoreSteps(wifiOff, false, false).isEmpty());

        check("null snapshot restores nothing",
                NetworkPlan.restoreSteps(null, false, false).isEmpty());
    }
}
