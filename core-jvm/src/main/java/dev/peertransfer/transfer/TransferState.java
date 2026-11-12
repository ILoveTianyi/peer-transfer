package dev.peertransfer.transfer;

/**
 * Session state machine (PROTOCOL.md §4). Illegal transitions throw instead of silently continuing: a
 * half-moved session that reports "done" is the failure this exists to prevent.
 */
public final class TransferState {

    public enum State {
        IDLE,
        PAIRING,
        NEGOTIATED,
        PREPARING,
        SENDING,
        VERIFYING,
        DONE,
        FAILED,
        CANCELLED
    }

    public static final class TransitionException extends IllegalStateException {

        private static final long serialVersionUID = 1L;

        TransitionException(String message) {
            super(message);
        }
    }

    private State state = State.IDLE;

    public State state() {
        return state;
    }

    public void paired() {
        expect(State.IDLE);
        state = State.PAIRING;
    }

    public void negotiated() {
        expect(State.PAIRING);
        state = State.NEGOTIATED;
    }

    public void preparing() {
        expect(State.NEGOTIATED);
        state = State.PREPARING;
    }

    public void sending() {
        expect(State.PREPARING);
        state = State.SENDING;
    }

    public void verifying() {
        expect(State.SENDING);
        state = State.VERIFYING;
    }

    public void done() {
        expect(State.VERIFYING);
        state = State.DONE;
    }

    public void fail() {
        if (state == State.DONE || state == State.FAILED || state == State.CANCELLED) {
            throw new TransitionException("cannot fail from " + state);
        }
        state = State.FAILED;
    }

    /**
     * Cancel is idempotent while a session is not finished: a user may tap cancel twice, and a
     * teardown path may run after an explicit cancel. Cancelling a completed or failed session is a
     * programming error and throws.
     */
    public void cancel() {
        if (state == State.DONE || state == State.FAILED) {
            throw new TransitionException("cannot cancel from " + state);
        }
        state = State.CANCELLED;
    }

    public boolean terminal() {
        return state == State.DONE || state == State.FAILED || state == State.CANCELLED;
    }

    private void expect(State required) {
        if (state != required) {
            throw new TransitionException("expected " + required + " but was " + state);
        }
    }
}
