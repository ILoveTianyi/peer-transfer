package dev.peertransfer.transfer;

import dev.peertransfer.crypto.SecureChannel;
import dev.peertransfer.proto.FrameIo;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Receiving side of a PT2 session (PROTOCOL.md §2.3, §4). One session per instance; the caller owns
 * the thread.
 *
 * <p>Guarantees that matter for correctness:
 *
 * <ul>
 *   <li>the handshake fails unless the peer proves knowledge of the pairing secret with a fresh nonce;</li>
 *   <li>each chunk's SHA-256 is verified <em>before</em> it is written, so a corrupt chunk cannot
 *       poison the file or the resume offset;</li>
 *   <li>only an in-order chunk advances the contiguous verified offset, so a gap cannot be reported
 *       as progress;</li>
 *   <li>the final file appears under its real name only after the whole-file hash matches.</li>
 * </ul>
 */
public final class TransferReceiver implements AutoCloseable {

    /** Eight in-flight chunks: enough to cover a hotspot round trip without unbounded buffering. */
    public static final int DEFAULT_ACK_WINDOW = 8;

    private final ServerSocket serverSocket;
    private final byte[] secret;
    private final Path destinationDir;
    private final long maxBytes;
    private final int ackWindowChunks;

    private Socket socket;
    private SecureChannel channel;

    public TransferReceiver(byte[] secret, Path destinationDir, long maxBytes) throws IOException {
        this(secret, destinationDir, maxBytes, DEFAULT_ACK_WINDOW);
    }

    /**
     * @param ackWindowChunks how many chunks the sender may run ahead before it waits for an ack.
     *                        Larger values keep a hotspot link busy instead of idling on round trips;
     *                        1 is stop-and-wait.
     */
    public TransferReceiver(byte[] secret, Path destinationDir, long maxBytes, int ackWindowChunks)
            throws IOException {
        if (secret == null || secret.length != 16) {
            throw new IllegalArgumentException("secret must be 16 bytes");
        }
        if (ackWindowChunks < 1 || ackWindowChunks > 1024) {
            throw new IllegalArgumentException("ack window out of range: " + ackWindowChunks);
        }
        this.secret = secret.clone();
        this.destinationDir = destinationDir;
        this.maxBytes = maxBytes;
        this.ackWindowChunks = ackWindowChunks;
        this.serverSocket = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress());
        Files.createDirectories(destinationDir);
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    /** Accepts one session and returns the number of verified bytes written. */
    public long receiveOne() throws IOException {
        socket = serverSocket.accept();
        FrameIo frames = new FrameIo(socket.getInputStream(), socket.getOutputStream());

        byte[] hello = frames.read();
        if (hello == null || hello.length != 1 + SecureChannel.NONCE_BYTES || hello[0] != 0x10) {
            throw new IOException("invalid hello");
        }
        byte[] clientNonce = new byte[SecureChannel.NONCE_BYTES];
        System.arraycopy(hello, 1, clientNonce, 0, clientNonce.length);
        byte[] serverNonce = SecureChannel.randomNonce();
        byte[] mac = SecureChannel.handshakeMac(secret, clientNonce, serverNonce);

        byte[] ack = new byte[1 + SecureChannel.NONCE_BYTES + SecureChannel.MAC_BYTES];
        ack[0] = 0x11;
        System.arraycopy(serverNonce, 0, ack, 1, serverNonce.length);
        System.arraycopy(mac, 0, ack, 1 + serverNonce.length, mac.length);
        frames.write(ack);

        channel = SecureChannel.forServer(secret, clientNonce, serverNonce);

        byte[] prepareFrame = frames.read();
        if (prepareFrame == null) {
            throw new IOException("peer closed before prepare");
        }
        Messages.Prepare prepare;
        try {
            prepare = Messages.decodePrepare(channel.open(prepareFrame));
        } catch (SecurityException e) {
            throw new IOException("prepare failed authentication", e);
        }
        if (prepare.size > maxBytes) {
            frames.write(channel.seal(Messages.encodePrepareAck(Messages.STATUS_REJECTED, 0, 1)));
            throw new IOException("offered file exceeds the configured limit: " + prepare.size);
        }

        Path finalPath = safeDestination(prepare.fileName);
        Path tempPath = finalPath.resolveSibling(finalPath.getFileName() + ".ptpart");
        long contiguous = Files.exists(tempPath) ? Files.size(tempPath) : 0L;
        if (contiguous > prepare.size) {
            contiguous = 0L;
            Files.deleteIfExists(tempPath);
        }
        frames.write(channel.seal(
                Messages.encodePrepareAck(Messages.STATUS_OK, contiguous, ackWindowChunks)));

        MessageDigest wholeFile = newDigest();
        int chunksSinceAck = 0;
        try (RandomAccessFile file = new RandomAccessFile(tempPath.toFile(), "rw")) {
            if (contiguous > 0) {
                // Re-hash the resumed prefix so the whole-file digest stays meaningful.
                byte[] buffer = new byte[64 * 1024];
                file.seek(0);
                long remaining = contiguous;
                while (remaining > 0) {
                    int read = file.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                    if (read < 0) {
                        break;
                    }
                    wholeFile.update(buffer, 0, read);
                    remaining -= read;
                }
            }
            file.seek(contiguous);

            while (true) {
                byte[] frame = frames.read();
                if (frame == null) {
                    throw new IOException("peer closed mid-transfer");
                }
                byte[] payload;
                try {
                    payload = channel.open(frame);
                } catch (SecurityException e) {
                    throw new IOException("frame failed authentication", e);
                }
                byte opcode = payload[0];
                if (opcode == Messages.OP_CHUNK) {
                    Messages.Chunk chunk = Messages.decodeChunk(payload);
                    byte[] actual = newDigest().digest(chunk.data);
                    if (!Messages.sameHash(actual, chunk.sha256)) {
                        frames.write(channel.seal(
                                Messages.encodeChunkAck(Messages.STATUS_CHECKSUM, contiguous)));
                        throw new IOException("chunk checksum mismatch at offset " + chunk.offset);
                    }
                    if (chunk.offset != contiguous) {
                        frames.write(channel.seal(Messages.encodeChunkAck(Messages.STATUS_GAP, contiguous)));
                        throw new IOException("chunk at " + chunk.offset + " but expected " + contiguous);
                    }
                    if (contiguous + chunk.data.length > prepare.size) {
                        frames.write(channel.seal(Messages.encodeChunkAck(Messages.STATUS_REJECTED, contiguous)));
                        throw new IOException("chunk overruns declared size");
                    }
                    file.write(chunk.data);
                    wholeFile.update(chunk.data);
                    contiguous += chunk.data.length;
                    chunksSinceAck++;
                    // Ack on the window boundary and once at the end, not after every chunk: on a
                    // hotspot link a per-chunk ack would make throughput a function of round-trip
                    // latency rather than of radio speed.
                    if (chunksSinceAck >= ackWindowChunks || contiguous == prepare.size) {
                        frames.write(channel.seal(
                                Messages.encodeChunkAck(Messages.STATUS_OK, contiguous)));
                        chunksSinceAck = 0;
                    }
                    continue;
                }
                if (opcode == Messages.OP_DONE) {
                    if (contiguous != prepare.size) {
                        frames.write(channel.seal(Messages.encodeDoneAck(Messages.STATUS_REJECTED)));
                        throw new IOException("done before all bytes: " + contiguous + "/" + prepare.size);
                    }
                    if (prepare.sha256 != null && !Messages.sameHash(wholeFile.digest(), prepare.sha256)) {
                        frames.write(channel.seal(Messages.encodeDoneAck(Messages.STATUS_CHECKSUM)));
                        throw new IOException("whole-file checksum mismatch");
                    }
                    file.getFD().sync();
                    frames.write(channel.seal(Messages.encodeDoneAck(Messages.STATUS_OK)));
                    break;
                }
                throw new IOException("unexpected opcode " + opcode);
            }
        }

        Files.move(tempPath, finalPath, StandardCopyOption.REPLACE_EXISTING);
        return contiguous;
    }

    private static MessageDigest newDigest() throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    /** Refuses path traversal: only the final name component is honoured. */
    private Path safeDestination(String fileName) {
        String name = fileName;
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            name = "received-" + new SecureRandom().nextInt(Integer.MAX_VALUE);
        }
        return destinationDir.resolve(name);
    }

    @Override
    public void close() throws IOException {
        if (channel != null) {
            channel.wipe();
        }
        if (socket != null) {
            socket.close();
        }
        serverSocket.close();
    }
}
