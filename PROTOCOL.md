# Peer Transfer Protocol (PT)

Normative specification for the transport this project implements. Version 1.

The design borrows its shape from [LocalSend Protocol v2.2](https://github.com/localsend/protocol)
(REST over HTTPS, multicast announce, prepare/upload session), because interoperating with LocalSend
peers is a goal. Where this document differs, the difference is deliberate and stated.

## 1. Roles and terms

- **Receiver** runs the listening socket. **Sender** connects. Exactly one side listens at a time.
- **Pairing** establishes: peer address, port, a shared 16-byte secret, and an expiry.
- **Session** is one accepted pairing plus one agreed protocol, identified by `sessionId`.

## 2. Pairing

Three pairing entry points produce the *same* 16-byte secret and address; only the carrier differs.

| Carrier | What travels | Consumer |
|---|---|---|
| QR | the encoded payload of §2.1 | camera scan |
| Bluetooth LE | the same payload bytes, chunked over a GATT characteristic | one central + one peripheral |
| NFC | the same payload bytes in an NDEF external record | tap (HCE or reader mode) |

Bluetooth and NFC never carry bulk data. They exist to move the payload and to wake the app; bulk
data always uses the Wi-Fi link from the payload.

### 2.1 Payload fields

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `50 54` (`PT`) |
| 2 | 1 | payload version = `1` |
| 3 | 1 | mode: `1` same-LAN, `2` hotspot peer |
| 4 | 1 | flags: bit0 receiver accepts TLS, bit1 receiver speaks LocalSend, bit2 a PIN is required |
| 5 | 2 | port (receiver's listening port) |
| 7 | 4 | expiry, unix seconds |
| 11 | 1 | length *n* of address (1–45) |
| 12 | *n* | address, UTF-8 textual IPv4 or IPv6 literal (**no** scope id, **no** brackets) |
| 12+*n* | 1 | length *m* of display name (0–64) |
| 13+*n* | *m* | display name, UTF-8 |
| 13+*n*+*m* | 16 | secret |
| 29+*n*+*m* | 2 | CRC-16/CCITT-FALSE over bytes `[0, 29+n+m)` |

Encoding for QR: base64url without padding. Total stays under 128 bytes, so a version-6 QR is
enough even with a long name.

### 2.2 Decoder obligations (all hard failures)

1. CRC mismatch → reject.
2. `payload version` unknown → reject.
3. Expired (`now >= expiry`) → reject.
4. Address that is not one of: IPv4 private (`10/8`, `172.16/12`, `192.168/16`), IPv6 unique-local
   (`fc00::/7`) → reject. Reject loopback, `0.0.0.0`, multicast, link-local (`169.254/16`,
   `fe80::/10`) and every public address. This prevents a crafted QR from turning the phone into a
   reachability oracle against an attacker-chosen host.
5. Name longer than 64 bytes, or non-UTF-8 → reject.

### 2.3 Proof of possession

The secret never travels after pairing. The sender proves it by sending

```
HMAC-SHA256(secret, "pt1-hello" || senderNonce(16) || receiverNonce(16))
```

in its first message. The receiver issues `receiverNonce` only in response to a fresh
`/pt1/hello`, keeps it for 60 seconds, and refuses a replayed nonce. A wrong HMAC closes the
socket without a distinguishable error, so an attacker learns nothing.

## 3. Negotiation ladder

Both sides send an ordered list of protocol identifiers they implement, highest first. The chosen
protocol is the first identifier in the **sender's** list that the receiver also lists.

| Identifier | Transport | Integrity | Resume | Notes |
|---|---|---|---|---|
| `pt2` | TLS 1.3, server certificate pinned by SPKI from pairing | per-chunk SHA-256 + whole-file SHA-256 | yes | preferred |
| `ls2.2` | HTTPS (LocalSend v2.2 REST) | whole-file SHA-256 when supplied | yes | interop |
| `ls2.0` | HTTPS (LocalSend v2.0/2.1 REST subset) | same | no | interop |
| `http1` | plain HTTP | whole-file SHA-256 | no | **only** with explicit user consent |

Rules:

- `http1` is never selected automatically. If the only common identifier is `http1` and the user has
  not consented, negotiation **fails** with `INSECURE_ONLY` rather than silently downgrading.
- An unknown identifier is ignored, not an error.
- If the lists are disjoint, fail with `NO_COMMON_PROTOCOL` and report both lists to the user.
- The chosen identifier is fixed for the session; renegotiation requires a new pairing.

## 4. Transfer

### 4.1 Prepare

`sender → receiver`: name, size, MIME type, whole-file SHA-256 (optional but recommended),
modification time (optional).

`receiver → sender`: accept / reject / accept-with-rename, plus `sessionId` and a per-file token.
A rejection carries a reason code so the sender can show it.

### 4.2 Chunks

Chunk size is 1 MiB except the last chunk. Chunks are addressed by absolute offset, so a resumed
transfer continues at a chunk boundary:

```
chunks(fileSize) = ceil(fileSize / 1 MiB)
chunk(i) = [i * 1MiB, min((i+1) * 1MiB, fileSize))
```

Each uploaded chunk is verified against its SHA-256 before it is appended. A mismatch aborts that
file, keeps the bytes up to the last good chunk, and reports the failing chunk index.

### 4.3 Resume

The receiver reports, per file, the number of contiguous verified bytes. The sender resumes at the
next chunk boundary at or after that number. A file whose whole-file SHA-256 does not match after
completion is deleted, never renamed into place.

### 4.4 Commit

Write to a temporary name, `fsync`, then rename. A partially received file never appears under its
final name.

## 5. Error codes

| Code | Meaning |
|---|---|
| `PT_OK` | success |
| `PT_E_CRC` | pairing payload CRC mismatch |
| `PT_E_EXPIRED` | pairing payload expired |
| `PT_E_ADDRESS` | address fails §2.2 rule 4 |
| `PT_E_AUTH` | proof of possession failed |
| `PT_E_NO_COMMON_PROTOCOL` | §3 lists disjoint |
| `PT_E_INSECURE_ONLY` | only `http1` common and no consent |
| `PT_E_BUSY` | receiver already in a session |
| `PT_E_REJECTED` | receiver declined |
| `PT_E_SPACE` | receiver out of space |
| `PT_E_CHECKSUM` | chunk or file hash mismatch |
| `PT_E_IO` | local I/O failure |

Codes are stable strings, not numbers, so a log line stays readable.

## 6. What this protocol does not do

- It does not provide confidentiality against a malicious **receiver** after the transfer; the
  receiver ends up with the plaintext by definition.
- It does not attempt NAT traversal, relay, or cloud storage.
- It does not authenticate the human on the far side beyond the pairing channel.
- It does not encrypt with a PSK: TLS 1.3 PSK is not reachable from Kotlin's `SSLSocket`.
