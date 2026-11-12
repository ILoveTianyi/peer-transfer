package dev.peertransfer.transfer;

import dev.peertransfer.crypto.SecureChannel;
import dev.peertransfer.proto.FrameIo;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Sending side of a PT2 session (PROTOCOL.md §2.3, §4).
 *
 * <p>Resume is driven by the receiver: the ack after PREPARE carries the contiguous verified prefix,
 * and this class continues at that byte offset. Each chunk is hashed locally and the hash travels with
 * it, so the receiver can reject a corrupt chunk without trusting the transport.
 */
public final class TransferSender implements AutoCloseable {

    private final String host;
    private final int port;
    private final byte[] secret;
    private final int chunkBytes;

    private Socket socket;
    private SecureChannel channel;

    public TransferSender(String host, int port, byte[] secret, int chunkBytes) {
        if (secret == null || secret.length != 16) {
            throw new IllegalArgumentException("secret must be 16 bytes");
        }
        if (chunkBytes <= 0 || chunkBytes > FrameIo.MAX_FRAME_BYTES - 128) {
            throw new IllegalArgumentException("chunk size out of range: " + chunkBytes);
        }
        this.host = host;
        this.port = port;
        this.secret = secret.clone();
        this.chunkBytes = chunkBytes;
    }

    public static final class Result {
        public final long bytesSent;
        public final boolean resumed;

        Result(long bytesSent, boolean resumed) {
            this.bytesSent = bytesSent;
            this.resumed = resumed;
        }
    }

    public Result send(Path source, String remoteName) throws IOException {
        byte[] wholeHash = sha256(Files.readAllBytes(source));
        long size = Files.size(source);
        socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), 10_000);
        FrameIo frames = new FrameIo(socket.getInputStream(), socket.getOutputStream());

        byte[] clientNonce = SecureChannel.randomNonce();
        byte[] hello = new byte[1 + clientNonce.length];
        hello[0] = 0x10;
        System.arraycopy(clientNonce, 0, hello, 1, clientNonce.length);
        frames.write(hello);

        byte[] ack = frames.read();
        if (ack == null || ack.length != 1 + SecureChannel.NONCE_BYTES + SecureChannel.MAC_BYTES
                || ack[0] != 0x11) {
            throw new IOException("invalid handshake ack");
        }
        byte[] serverNonce = Arrays.copyOfRange(ack, 1, 1 + SecureChannel.NONCE_BYTES);
        byte[] mac = Arrays.copyOfRange(ack, 1 + SecureChannel.NONCE_BYTES, ack.length);
        if (!SecureChannel.verifyHandshakeMac(secret, clientNonce, serverNonce, mac)) {
            throw new IOException("peer failed proof of possession");
        }

        channel = SecureChannel.forClient(secret, clientNonce, serverNonce);
        frames.write(channel.seal(Messages.encodePrepare(
                new Messages.Prepare(remoteName, size, wholeHash))));

        byte[] prepareAck = channel.open(frames.read());
        byte status = Messages.decodePrepareAckStatus(prepareAck);
        long startOffset = Messages.decodePrepareAckOffset(prepareAck);
        if (status != Messages.STATUS_OK) {
            throw new IOException("receiver rejected the transfer, status " + status);
        }
        if (startOffset > size) {
            throw new IOException("receiver claimed a resume offset beyond the file");
        }

        ChunkPlan plan = new ChunkPlan(size, chunkBytes);
        long sent = 0;
        try (java.io.RandomAccessFile file = new java.io.RandomAccessFile(source.toFile(), "r")) {
            int index = plan.resumeIndex(startOffset);
            byte[] buffer = new byte[chunkBytes];
            while (index < plan.chunkCount()) {
                ChunkPlan.Chunk chunk = plan.chunk(index);
                file.seek(chunk.offset());
                file.readFully(buffer, 0, chunk.length());
                byte[] data = chunk.length() == buffer.length
                        ? buffer.clone()
                        : Arrays.copyOf(buffer, chunk.length());
                frames.write(channel.seal(Messages.encodeChunk(chunk.offset(), data, sha256(data))));
                sent += data.length;

                byte[] chunkAck = channel.open(frames.read());
                byte chunkStatus = Messages.decodeChunkAckStatus(chunkAck);
                if (chunkStatus != Messages.STATUS_OK) {
                    throw new IOException("receiver rejected chunk at " + chunk.offset()
                            + ", status " + chunkStatus);
                }
                index++;
            }
        }

        frames.write(channel.seal(Messages.encodeDone()));
        byte doneStatus = Messages.decodeDoneAck(channel.open(frames.read()));
        if (doneStatus != Messages.STATUS_OK) {
            throw new IOException("receiver reported failure at completion, status " + doneStatus);
        }
        return new Result(sent, startOffset > 0);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() throws IOException {
        if (channel != null) {
            channel.wipe();
        }
        if (socket != null) {
            socket.close();
        }
    }
}
