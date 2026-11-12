package dev.peertransfer.transfer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The messages carried inside a sealed frame (PROTOCOL.md §4).
 *
 * <p>Binary, not JSON: the chunk header sits in the hot path, and a fixed layout gives a predictable
 * per-chunk overhead. Every decode validates lengths before allocation, because the payload arrives
 * from the peer.
 */
public final class Messages {

    public static final byte OP_PREPARE = 1;
    public static final byte OP_PREPARE_ACK = 2;
    public static final byte OP_CHUNK = 3;
    public static final byte OP_CHUNK_ACK = 4;
    public static final byte OP_DONE = 5;
    public static final byte OP_DONE_ACK = 6;

    public static final byte STATUS_OK = 0;
    public static final byte STATUS_REJECTED = 1;
    public static final byte STATUS_CHECKSUM = 2;
    public static final byte STATUS_GAP = 3;
    public static final byte STATUS_IO = 4;

    public static final int HASH_BYTES = 32;

    private Messages() {
    }

    public static final class Prepare {
        public final String fileName;
        public final long size;
        public final byte[] sha256;

        public Prepare(String fileName, long size, byte[] sha256) {
            if (fileName == null || fileName.isEmpty()
                    || fileName.getBytes(StandardCharsets.UTF_8).length > 512) {
                throw new IllegalArgumentException("invalid file name");
            }
            if (size < 0) {
                throw new IllegalArgumentException("negative size");
            }
            if (sha256 != null && sha256.length != HASH_BYTES) {
                throw new IllegalArgumentException("sha256 must be 32 bytes");
            }
            this.fileName = fileName;
            this.size = size;
            this.sha256 = sha256 == null ? null : sha256.clone();
        }
    }

    public static byte[] encodePrepare(Prepare prepare) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(OP_PREPARE);
            byte[] name = prepare.fileName.getBytes(StandardCharsets.UTF_8);
            out.writeShort(name.length);
            out.write(name);
            out.writeLong(prepare.size);
            out.writeByte(prepare.sha256 == null ? 0 : 1);
            if (prepare.sha256 != null) {
                out.write(prepare.sha256);
            }
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Prepare decodePrepare(byte[] payload) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        requireOpcode(in, OP_PREPARE);
        int nameLength = in.readUnsignedShort();
        if (nameLength < 1 || nameLength > 512) {
            throw new IOException("invalid name length " + nameLength);
        }
        byte[] name = new byte[nameLength];
        in.readFully(name);
        long size = in.readLong();
        int hasHash = in.readUnsignedByte();
        byte[] hash = null;
        if (hasHash == 1) {
            hash = new byte[HASH_BYTES];
            in.readFully(hash);
        } else if (hasHash != 0) {
            throw new IOException("invalid hash flag " + hasHash);
        }
        return new Prepare(new String(name, StandardCharsets.UTF_8), size, hash);
    }

    /**
     * PREPARE_ACK: status(1) || resumeOffset(8) || ackWindow(4).
     *
     * <p>The window is how many chunks the sender may have in flight before it must read an ack. The
     * receiver dictates it because it knows its own write speed; a window of 1 degenerates to
     * stop-and-wait, which is what a single-chunk-per-ack design would force over a link with any
     * round-trip latency.
     */
    public static byte[] encodePrepareAck(byte status, long resumeOffset, int ackWindow) {
        byte[] payload = new byte[21];
        payload[0] = OP_PREPARE_ACK;
        payload[1] = status;
        for (int i = 0; i < 8; i++) {
            payload[9 + i] = (byte) (resumeOffset >>> (56 - 8 * i));
        }
        for (int i = 0; i < 4; i++) {
            payload[17 + i] = (byte) (ackWindow >>> (24 - 8 * i));
        }
        return payload;
    }

    public static byte decodePrepareAckStatus(byte[] payload) throws IOException {
        requirePrepareAck(payload);
        return payload[1];
    }

    public static long decodePrepareAckOffset(byte[] payload) throws IOException {
        requirePrepareAck(payload);
        long value = 0;
        for (int i = 9; i < 17; i++) {
            value = (value << 8) | (payload[i] & 0xFF);
        }
        return value;
    }

    public static int decodePrepareAckWindow(byte[] payload) throws IOException {
        requirePrepareAck(payload);
        int value = 0;
        for (int i = 17; i < 21; i++) {
            value = (value << 8) | (payload[i] & 0xFF);
        }
        return value < 1 ? 1 : value;
    }

    private static void requirePrepareAck(byte[] payload) throws IOException {
        if (payload.length != 21 || payload[0] != OP_PREPARE_ACK) {
            throw new IOException("invalid prepare ack");
        }
    }

    public static byte[] encodeChunk(long offset, byte[] data, byte[] sha256) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(1 + 8 + 4 + data.length + HASH_BYTES);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(OP_CHUNK);
            out.writeLong(offset);
            out.writeInt(data.length);
            out.write(data);
            out.write(sha256);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static final class Chunk {
        public final long offset;
        public final byte[] data;
        public final byte[] sha256;

        Chunk(long offset, byte[] data, byte[] sha256) {
            this.offset = offset;
            this.data = data;
            this.sha256 = sha256;
        }
    }

    public static Chunk decodeChunk(byte[] payload) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        requireOpcode(in, OP_CHUNK);
        long offset = in.readLong();
        int length = in.readInt();
        if (offset < 0 || length < 1 || length > payload.length) {
            throw new IOException("invalid chunk header offset=" + offset + " length=" + length);
        }
        if (payload.length != 1 + 8 + 4 + length + HASH_BYTES) {
            throw new IOException("chunk length mismatch");
        }
        byte[] data = new byte[length];
        in.readFully(data);
        byte[] hash = new byte[HASH_BYTES];
        in.readFully(hash);
        return new Chunk(offset, data, hash);
    }

    public static byte[] encodeChunkAck(byte status, long contiguousVerified) {
        byte[] payload = new byte[10];
        payload[0] = OP_CHUNK_ACK;
        payload[1] = status;
        for (int i = 0; i < 8; i++) {
            payload[2 + i] = (byte) (contiguousVerified >>> (56 - 8 * i));
        }
        return payload;
    }

    public static byte decodeChunkAckStatus(byte[] payload) throws IOException {
        if (payload.length != 10 || payload[0] != OP_CHUNK_ACK) {
            throw new IOException("invalid chunk ack");
        }
        return payload[1];
    }

    public static long decodeChunkAckContiguous(byte[] payload) throws IOException {
        if (payload.length != 10 || payload[0] != OP_CHUNK_ACK) {
            throw new IOException("invalid chunk ack");
        }
        long value = 0;
        for (int i = 2; i < 10; i++) {
            value = (value << 8) | (payload[i] & 0xFF);
        }
        return value;
    }

    public static byte[] encodeDone() {
        return new byte[]{OP_DONE};
    }

    public static byte[] encodeDoneAck(byte status) {
        return new byte[]{OP_DONE_ACK, status};
    }

    public static byte decodeDoneAck(byte[] payload) throws IOException {
        if (payload.length != 2 || payload[0] != OP_DONE_ACK) {
            throw new IOException("invalid done ack");
        }
        return payload[1];
    }

    public static boolean sameHash(byte[] left, byte[] right) {
        return left != null && right != null && Arrays.equals(left, right);
    }

    private static void requireOpcode(DataInputStream in, byte expected) throws IOException {
        int opcode = in.readUnsignedByte();
        if (opcode != expected) {
            throw new IOException("unexpected opcode " + opcode + ", wanted " + expected);
        }
    }
}
