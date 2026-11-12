# peer-transfer

Independent cross-platform peer file transfer for Android and Windows.

Pairing by QR code, Bluetooth, or NFC tap; bulk data over a negotiated Wi-Fi link;
the original Wi-Fi state is restored when the transfer ends.

## Status — read this first

| Part | State |
|---|---|
| Wire protocol specification | written ([PROTOCOL.md](PROTOCOL.md)) |
| Pairing payload codec, negotiation, transfer planning, network plan | **implemented, unit-tested on a bare JVM** (`core-jvm/`) |
| Windows core (same codecs) | **implemented, unit-tested; 47 checks, crosses the shared vectors** |
| Android app (UI, QR/BLE/NFC entry points, foreground service, notification) | scaffold only — **not built, not run on a device** |
| LocalSend interop | specified, **not implemented** |
| End-to-end transfer between two real devices | **not verified** |

Anything not listed as implemented is not claimed to work. In particular there has been no
end-to-end transfer between two real devices; the JVM and .NET tests cover encoders, state machines
and planners, not sockets, radios, or file systems.

## Why not fork LocalSend

[LocalSend](https://github.com/localsend/localsend) is the reference design and an interop target,
not the base: this project needs a protocol ladder (so two peers use the highest scheme they both
support), Android-specific network restoration, and a Windows client sharing one test-vector set.
See [docs/COMPARISON.md](docs/COMPARISON.md) for what was borrowed and what was deliberately not.

## Layout

```
PROTOCOL.md              wire format, pairing, negotiation ladder, transfer, error codes
docs/NETWORK.md          Wi-Fi capture/restore contract and the concurrent-network limits
docs/COMPARISON.md       relationship to LocalSend
core-jvm/                Android-free Java core + tests (javac / java, no third-party deps)
shared/test-vectors/     canonical vectors both platform implementations must satisfy
android/                 Android app scaffold
windows/                 Windows client core + tests
```

## Verify the core

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File core-jvm/build.ps1
```

It compiles with `javac` and runs the assertion suite; no Gradle, no network, no device.

```
CHECKS: 99 run, 0 failed
tests OK
```
