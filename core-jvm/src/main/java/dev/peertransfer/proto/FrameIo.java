package dev.peertransfer.proto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Length-prefixed frame transport (PROTOCOL.md §2.3, §3).
 *
 * <p>Every frame is {@code uint32 length || payload}, with a hard ceiling so a hostile peer cannot ask
 * this side to allocate an arbitrary buffer. Length is validated before reading, which is the whole
 * point of the prefix.
 */
public final class FrameIo {

    /** 8 MiB: one 1 MiB chunk plus seal overhead plus future metadata has plenty of room. */
    public static final int MAX_FRAME_BYTES = 8 * 1024 * 1024;

    private final DataInputStream in;
    private final DataOutputStream out;

    public FrameIo(InputStream input, OutputStream output) {
        this.in = new DataInputStream(input);
        this.out = new DataOutputStream(output);
    }

    public void write(byte[] payload) throws IOException {
        if (payload.length > MAX_FRAME_BYTES) {
            throw new IOException("frame too large to send: " + payload.length);
        }
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    public byte[] read() throws IOException {
        int length;
        try {
            length = in.readInt();
        } catch (EOFException e) {
            return null; // clean end of stream
        }
        if (length < 1 || length > MAX_FRAME_BYTES) {
            throw new IOException("refusing frame length " + length);
        }
        byte[] payload = new byte[length];
        in.readFully(payload);
        return payload;
    }
}
