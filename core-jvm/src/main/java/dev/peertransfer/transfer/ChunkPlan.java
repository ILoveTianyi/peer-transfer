package dev.peertransfer.transfer;

import java.util.ArrayList;
import java.util.List;

/**
 * Chunk arithmetic and resume decisions (PROTOCOL.md §4.2, §4.3).
 *
 * <p>Offsets are absolute, so a resumed transfer always continues on a chunk boundary; a receiver
 * that reports "n contiguous verified bytes" gets the next chunk that starts at or after n.
 */
public final class ChunkPlan {

    public static final int DEFAULT_CHUNK_BYTES = 1024 * 1024;

    public static final class Chunk {
        private final int index;
        private final long offset;
        private final int length;

        Chunk(int index, long offset, int length) {
            this.index = index;
            this.offset = offset;
            this.length = length;
        }

        public int index() {
            return index;
        }

        public long offset() {
            return offset;
        }

        public int length() {
            return length;
        }

        public long endExclusive() {
            return offset + length;
        }

        @Override
        public String toString() {
            return "#" + index + "[" + offset + "," + endExclusive() + ")";
        }
    }

    private final long fileSize;
    private final int chunkBytes;

    public ChunkPlan(long fileSize, int chunkBytes) {
        if (fileSize < 0) {
            throw new IllegalArgumentException("negative file size");
        }
        if (chunkBytes <= 0) {
            throw new IllegalArgumentException("chunk size must be positive");
        }
        this.fileSize = fileSize;
        this.chunkBytes = chunkBytes;
    }

    public ChunkPlan(long fileSize) {
        this(fileSize, DEFAULT_CHUNK_BYTES);
    }

    public long fileSize() {
        return fileSize;
    }

    public int chunkBytes() {
        return chunkBytes;
    }

    public int chunkCount() {
        if (fileSize == 0) {
            return 0;
        }
        return (int) ((fileSize + chunkBytes - 1) / chunkBytes);
    }

    public Chunk chunk(int index) {
        int count = chunkCount();
        if (index < 0 || index >= count) {
            throw new IndexOutOfBoundsException("chunk " + index + " of " + count);
        }
        long offset = (long) index * chunkBytes;
        int length = (int) Math.min(chunkBytes, fileSize - offset);
        return new Chunk(index, offset, length);
    }

    public List<Chunk> all() {
        List<Chunk> chunks = new ArrayList<Chunk>(chunkCount());
        for (int i = 0; i < chunkCount(); i++) {
            chunks.add(chunk(i));
        }
        return chunks;
    }

    /**
     * Index of the first chunk that still needs sending given {@code contiguousVerifiedBytes} already
     * on the receiver. Equal to {@link #chunkCount()} when the file is complete.
     */
    public int resumeIndex(long contiguousVerifiedBytes) {
        if (contiguousVerifiedBytes < 0) {
            throw new IllegalArgumentException("negative verified byte count");
        }
        if (contiguousVerifiedBytes >= fileSize) {
            return chunkCount();
        }
        long index = contiguousVerifiedBytes / chunkBytes;
        return (int) index;
    }

    /** Remaining chunks after a resume point, used to size progress reporting. */
    public List<Chunk> remaining(long contiguousVerifiedBytes) {
        List<Chunk> chunks = new ArrayList<Chunk>();
        for (int i = resumeIndex(contiguousVerifiedBytes); i < chunkCount(); i++) {
            chunks.add(chunk(i));
        }
        return chunks;
    }
}
