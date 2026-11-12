# Relationship to LocalSend

[LocalSend](https://github.com/localsend/localsend) is the reference for this project. Its
[protocol v2.2](https://github.com/localsend/protocol) is the interop target: a Peer Transfer client
should exchange files with an unmodified LocalSend peer when both sides support the same dialect.

## Borrowed

| Idea | Why it is right |
|---|---|
| Exactly one side listens; the receiver hosts | removes a class of NAT and firewall questions |
| REST endpoints `prepare-upload`, `upload`, `cancel` | simple, inspectable, testable with curl |
| Multicast announce plus HTTP registration fallback | networks that filter multicast still work |
| Fingerprint to avoid self-discovery | practical, and the same field distinguishes peers |
| A secret in the QR, proof of knowledge at connect | TLS-PSK is unreachable from Kotlin's `SSLSocket` |
| Receiver verifies a whole-file SHA-256 | cheap, and catches corruption the transport misses |

## Deliberately different

| Ours | LocalSend | Reason |
|---|---|---|
| Explicit ladder that **refuses** when only plaintext is common | HTTPS by default, plaintext mode exists | a silent downgrade is the failure mode we care about |
| Per-chunk SHA-256 in `pt2` | whole-file hash only | a truncated resume must not look complete |
| One canonical payload layout for QR, BLE and NFC | QR-centric | one encoder, one decoder, one vector set; carriers cannot drift |
| Network strategy before sockets, restore in `finally` | not part of the protocol | this is where "internet stayed up" is true or not |
| Windows client shares the JVM test vectors | — | implementations are checked against bytes, not against each other |

## Not borrowed on purpose

- **Scanning every address on the subnet.** Unrequested traffic, unreliable with client isolation.
- **A long-running listening port.** The socket exists only for an accepted session with an expiry.
- **A GUI-first implementation.** The protocol and state machine are Android-free so they can be
  verified on a JVM before any radio is involved.

## Interop status

`ls2.2` / `ls2.0` appear in the ladder but the REST endpoints are **not implemented** — a LocalSend
peer would currently negotiate to nothing, and the session is refused with
`PT_E_NO_COMMON_PROTOCOL` if `pt2` is unavailable. Interop is a later milestone, not a claim.
