# Wi-Fi behaviour: strategy before sockets, restore in `finally`

Two questions are answered before the app opens a socket, and both are implemented in the tested core
(`dev.peertransfer.net.NetworkPlan`).

## 1. Can the transfer link coexist with the user's internet?

| Situation | Decision |
|---|---|
| Peer is already on the same network | `USE_EXISTING_NETWORK` — nothing about Wi-Fi changes |
| Device reports concurrent networks | `SECONDARY_LINK_KEEP_INTERNET` — the internet connection stays up |
| No concurrency, user did not ask to keep internet | `PRIVATE_LINK_MAY_PAUSE_INTERNET` |
| No concurrency, user asked to keep internet, no consent to pause | `REFUSE_WOULD_DROP_INTERNET` — **refuse and explain** |
| No concurrency, user accepted a pause | `PRIVATE_LINK_MAY_PAUSE_INTERNET`, with a warning string for the UI |

**The honest limit.** Android applications cannot force two Wi-Fi roles to stay up on hardware that
lacks concurrent operation. What an app can do is detect the capability, prefer a link that does not
disturb the primary connection, and ask before disturbing it. That is why the no-concurrency case is
a refusal at plan time rather than a retry loop at runtime: a retry cannot create a capability.

## 2. What has to be put back

`restoreSteps(before, wifiEnabledAfter, onPreviousNetworkAfter)` returns an ordered list:

1. `REENABLE_WIFI` — only if Wi-Fi was on before and is off now.
2. `RECONNECT_PREVIOUS_NETWORK` — only if a network was known before and is not the current one.
3. `WAIT_FOR_INTERNET_VALIDATION` — appended only when the list is non-empty.

An unchanged state produces an empty list: a restore that would be a no-op is not reported as work.

## 3. Why the restore lives in `finally`

The restore obligation is created when the link is taken. If it were on the success path only, a
cancelled or crashed transfer would leave the device without its network. `TransferService` therefore
snapshots before, and restores in a `finally`, so cancel and failure take the same path as success.

## 4. Not implemented yet

- The `WifiManager` / `WifiP2pManager` calls that produce the snapshot and execute the actions.
- Observation of `ConnectivityManager` validation to know when step 3 is actually complete.
- Airplane-mode restore (`RESTORE_AIRPLANE_MODE` exists in the enum; nothing produces it because the
  app must never turn airplane mode off on its own).

## 5. What the notification must show

Peer name, the chosen protocol (so a downgrade is visible), the file being serialised, percent, and —
while restoring — the restore step in progress. Progress the notification cannot show is progress the
user cannot trust.
