# Umsetzungsplan: Traffic-Flow-Logging für OSS-NetBird

Eigenbetrieb auf öffentlichem Fork `github.com/ahlner/netbird` (AGPL-Quelloffenlegung
des Management-Forks dadurch abgedeckt). Kein Upstream-PR, keine Änderung am Agenten.

## Kontext (verifizierter Ist-Stand, Repo-Stand September 2026)

- **Agent-Seite vollständig:** `client/internal/netflow/` (conntrack im Kernel-Modus,
  `uspfilter` im Userspace-Modus, Aggregation, Retry/Ack, gRPC-Versand),
  `flow/client/` (Handshake `IsInitiator`, `Bearer <signature>.<payload>`-Auth,
  Resend bis Ack, Backoff bis 3 Monate), Protokoll `flow/proto/flow.proto`
  (`FlowService.Events` bidi-stream; jedes `FlowEvent` braucht `FlowEventAck`).
- **Draht vorhanden:** `NetbirdConfig.Flow` (`shared/management/proto/management.proto:358`,
  Felder url/tokenPayload/tokenSignature/interval[Duration, Pflicht]/enabled/counters/
  exitNodeCollection/dnsCollection). Agent wertet sie pro Sync aus
  (`client/internal/engine.go:1185-1219`).
- **Blocker:** Stub-Modul `github.com/netbirdio/management-integrations/integrations`
  (go.mod require; per `replace` auf `fork/integrations` umgeleitet).
  `ExtendNetBirdConfig` ist dort No-op, `extra_settings.Manager` liefert leere Settings.
- **Aufrufstellen der Integrations-API im OSS:**
  `management/internals/shared/grpc/conversion.go:176` (+ `token_mgr.go:293`,
  `components_envelope_response.go:79`) für `config.ExtendNetBirdConfig`;
  `management/internals/server/modules.go:73` und
  `management/server/http/testing/testing_tools/channel/channel.go` für
  `integrations.NewManager`/`NewController`.
- **`peerGroups` = Gruppen-IDs** (`GetPeerGroupIDs`, server.go:1017) — Gruppen werden
  per ID gematcht, nicht per Name. Gruppen-ID im Dashboard (Gruppeneinstellungen/URL)
  oder via `GET /api/groups`.
- **REST-Felder** `settings.extra.network_traffic_logs_*` sind bis `ExtraSettings`
  verdrahtet, ohne Fork wirkungslos (`gorm:"-"`, keine Persistenz).

## Teil A: Management-Fork (in dieser Änderung umgesetzt)

Eigenes Modul `fork/integrations/` mit Modulpfad
`github.com/netbirdio/management-integrations/integrations`, aktiviert durch genau eine
Zeile in der Root-`go.mod`:

```
replace github.com/netbirdio/management-integrations/integrations => ./fork/integrations
```

- Spiegelt die komplette Stub-Oberfläche 1:1 (Dateilayout identisch:
  `integrations.go`, `extra_settings.go`, `port_forwarding.go`, `validator.go`,
  `config/config.go`), damit künftige Upstream-API-Änderungen laut am Kompiler
  scheitern statt still zu kippen.
- **Aktivierungsregel:** Flow nur, wenn `NB_FLOW_GROUPS` **und** `NB_FLOW_RECEIVER_URL`
  **und** `NB_FLOW_SIGNING_KEY` gesetzt sind; sonst deaktiviert + Warnlog.
- **Pro-Peer-Scoping:** Peer loggt, wenn `peerGroups ∩ NB_FLOW_GROUPS ≠ ∅`.
  Ein/Aus pro Peer zur Laufzeit über Gruppenmitgliedschaft (nächster Sync schaltet um).
  Verkehre Gruppenpeer↔Nicht-Gruppenpeer werden einfach, Gruppenpeer↔Gruppenpeer
  doppelt gemeldet (akzeptiert; Merge im Receiver später).
- **`GetExtraSettings`:** Konstanten aus Env (FlowEnabled, FlowGroups,
  FlowPacketCounterEnabled=true, DNS-/EN-Collection per Env). `UpdateExtraSettings`
  no-op → REST-PUT auf `network_traffic_logs_*` bleibt wirkungslos (bewusst, POC).
- **`ExtendNetBirdConfig`:** setzt `FlowConfig` mit URL/Interval aus Env und Token
  `payload = base64url(JSON{peer_id, iat, exp})`, `signature = base64url(HMAC-SHA256
  (secret, payload))`; Agent sendet `Bearer <signature>.<payload>`.

### Env-Variablen (Management-Prozess)

| Variable | Zweck | Default |
| --- | --- | --- |
| `NB_FLOW_GROUPS` | Komma-separierte **Gruppen-IDs** der meldenden Peers (Pflicht) | leer = aus |
| `NB_FLOW_RECEIVER_URL` | gRPC-Ziel des Receivers, z. B. `https://flows.example.com:443` (Pflicht) | leer = aus |
| `NB_FLOW_SIGNING_KEY` | HMAC-Secret für Agent-Tokens (Pflicht) | leer = aus |
| `NB_FLOW_INTERVAL` | Sendeintervall der Agents, Go-Duration | `5m` |
| `NB_FLOW_DNS_COLLECTION` | `true` = DNS-Flows miterfassen | `false` |
| `NB_FLOW_EXITNODE_COLLECTION` | `true` = Exit-Node-/Exit-Route-Flows miterfassen | `false` |

## Teil B: Flow-Receiver (Folgeschritt, noch nicht gebaut)

Eigenes Binary `cmd/flowreceiver/`, separater Prozess, lizenzfrei wählbar, solange es
das Management nur per Netzprotokoll (gRPC in, REST für Anreicherung) anspricht:

1. `FlowService.Events`-Server: Handshake (`Ack{IsInitiator:true}` nach erstem
   `FlowEvent{IsInitiator:true}` mit Headern), dann pro Event `FlowEventAck{EventId}`.
   Referenzimplementierung: Fake-Server in `flow/client/client_test.go`.
2. Auth: `authorization`-Metadata, HMAC-Signatur + `exp` prüfen (Secret wie Management).
3. TLS in Produktion (Client nutzt System-CAs + embedded-roots-Fallback bei https).
4. Dedup über `event_id` (Client sendet unbestätigte Events erneut, auch über Restarts).
5. Storage v1: JSONL, alle `FlowFields` inkl. rx/tx, `num_of_*`, `window_start/end`.
6. Anreicherung (Phase 2): `GET /api/peers` (ip→Name/User/Gruppen; Reporter über
   `direction`: egress=Quelle, ingress=Ziel), `/api/users`, `/api/policies` (rule_id),
   `/api/networks` (resource_id); PAT-Service-User, Cache + refresh-on-miss.
   `public_key` liegt nicht im REST-API → roh mitspeichern.
7. Betrieb: Receiver muss von jedem meldenden Peer erreichbar sein (direkter Pfad,
   Management liegt nicht im Datenweg; z. B. Receiver selbst als Peer oder öffentlich
   mit TLS). Bei Receiver-Ausfall puffert jeder meldende Agent nach (ungebundener
   In-Memory-Puffer, Retry bis 3 Monate) → Verfügbarkeit beachten.

## Verifikation

- `go build ./management/...` (und später `./...`) grün.
- Management mit Envs starten → Sync enthält `flow`-Block (im Management-Debuglog bzw.
  Agent-Log `flow` enabled); Gruppenmitgliedschaft toggelt live pro Peer.
- Receiver-Schritt: Integrationstest mit echtem `flow/client` (Muster aus
  `client_test.go`), danach Labor-VM (nur Wegwerfumgebung, Agent läuft als root):
  Events kommen an, Acks drainen den Puffer, Receiver-Restart → Resend+Dedup greift,
  danach `netbird down` für sauberes Teardown.
- `go fmt`, `make lint` auf geänderte Dateien; neue Dateien mit SPDX-Headern.

## Lizenz

- `fork/integrations/`: BSD-3-Clause (AGPL-kompatibel), SPDX-Header pro Datei.
- Management-Binary bleibt insgesamt AGPLv3; Fork ist öffentlich → §13 abgedeckt.
- Keine Hand-Edits an generierten Dateien, keine Änderungen an OSS-Quelldateien
  außer der einen `replace`-Zeile in `go.mod`.

## Beauftragungstext für den Receiver (später)

> „Baue cmd/flowreceiver wie in PLAN-traffic-flow.md Teil B: FlowService.Events mit
> Handshake+Acks, HMAC-Auth gegen NB_FLOW_SIGNING_KEY, Dedup via event_id, JSONL-
> Storage, Verifikation mit echtem flow/client."
