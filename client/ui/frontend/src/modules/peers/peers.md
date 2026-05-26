# Peers — info missing in PeersList.tsx

`PeersList.tsx` currently shows only: `connStatus` (dot), `fqdn`, `ip`.

`screens/Peers.tsx` additionally surfaces the following fields from `PeerStatus`:

## Row chrome (collapsed)
- `peer.relayed` — Network (relayed, yellow) vs Zap (P2P, green) icon, gated on `connStatus === "Connected"`.
- `peer.rosenpassEnabled` — ShieldCheck icon when true.
- `peer.latencyMs` — `"{n} ms"` on the right when Connected and > 0.

## Top-level controls
- Filter input — matches against `fqdn`, `ip`, and each entry in `networks`.
- Peer count — `status.peers.length` next to the title.
- Expand/collapse per row (chevron).

## Expanded details panel
- `peer.pubKey` — Public key (mono).
- `peer.lastHandshakeUnix` — Last handshake (relative time).
- `peer.connStatusUpdateUnix` — Status since (relative time).
- `peer.bytesRx` / `peer.bytesTx` — formatted B/KB/MB/GB.
- `peer.localIceCandidateType` + `peer.localIceCandidateEndpoint` — Local candidate.
- `peer.remoteIceCandidateType` + `peer.remoteIceCandidateEndpoint` — Remote candidate.
- `peer.relayAddress` — shown only when `peer.relayed`.
- `peer.networks` — joined list, shown when non-empty.

## `PeerStatus` interface (from `@bindings/services/models.js`)
```ts
interface PeerStatus {
  ip: string;
  pubKey: string;
  connStatus: string;                  // "Connected" | "Connecting" | "Idle" | ...
  connStatusUpdateUnix: number;
  relayed: boolean;
  localIceCandidateType: string;
  remoteIceCandidateType: string;
  localIceCandidateEndpoint: string;
  remoteIceCandidateEndpoint: string;
  fqdn: string;
  bytesRx: number;
  bytesTx: number;
  latencyMs: number;
  relayAddress: string;
  lastHandshakeUnix: number;
  rosenpassEnabled: boolean;
  networks: string[];
}
```
