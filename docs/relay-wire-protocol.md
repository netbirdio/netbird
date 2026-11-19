# Relay wire protocol

This document describes what a NetBird relay server and a relay client exchange on the
wire: the transports, the message format, the handshake, forwarding, peer state
notifications and health checks. It is written for anyone who implements a relay server
or client independently of the Go code in this repository. The Go code remains the
reference; where this document and the code disagree, the code is right and this
document has a bug.

## Overview

A relay forwards opaque packets between peers that cannot reach each other directly. In
NetBird those packets are WireGuard packets, but the relay does not inspect them.

- Each peer keeps one connection to a relay server. All of its relayed traffic, to every
  other peer, rides that one connection.
- A peer is known to the relay by a 36-byte peer ID. The relay routes each packet by the
  destination peer ID carried in the packet.
- The relay forwards only between peers connected to the same relay server. Two peers on
  different relay servers use one common server: a peer learns the other peer's relay
  address through the Signal service and opens a second connection to that server.

## Transports

A relay server listens on one address with two transports: WebSocket on TCP and QUIC on
UDP, on the same port number. The port is deployment-specific.

### Relay addresses

A relay address uses the scheme `rels://` (TLS) or `rel://` (no TLS), for example
`rels://relay.example.com:443`. Without a port, clients use 443 for `rels://` and 80 for
`rel://`. The server's own address, its instance URL, is built from its configured
exposed address and is returned to every client in the handshake.

### WebSocket

| Aspect | Value |
|---|---|
| URL | `rels://host:port` becomes `wss://host:port/relay`; `rel://` becomes `ws://`. The path is always `/relay`. |
| TLS | Present for `rels://`, absent for `rel://`. The relay uses the TLS configuration it is given; it sets no ALPN value of its own. |
| Upgrade | HTTP/1.1 WebSocket upgrade. No subprotocol. Any `Origin` is accepted. The server allows 5 seconds to read the request headers. |
| Framing | One relay message is one binary WebSocket message. Text messages are an error and end the connection. |
| Message size | At most 8820 bytes (`MaxMessageSize`). |
| Writes | The server gives each write 10 seconds. |
| Keepalive | The relay's own health check messages (see [Health checks](#health-checks)). The protocol does not depend on WebSocket ping and pong. |
| Client address | `X-Real-Ip` and `X-Real-Port` headers replace the remote address in logs and metrics only when the request comes from a configured trusted proxy. |

### QUIC

| Aspect | Value |
|---|---|
| Availability | Only when the server has a TLS configuration. A server without TLS offers WebSocket only. |
| ALPN | `nb-quic` |
| Framing | One relay message is one QUIC DATAGRAM frame (RFC 9221). The relay opens no streams. Datagrams are unreliable and unordered: a lost datagram is not retransmitted. |
| Initial packet size | 1232 bytes (`QUICInitialPacketSize`). |
| Message size | At most 1188 bytes (`QUICMaxDatagramSize`): the largest DATAGRAM payload that fits a 1232-byte packet with every header field at its longest. |
| Client settings | Keepalive period 30 seconds, maximum idle timeout 4 minutes, 0-RTT off. The server uses the QUIC library defaults for idle timeout. |
| Close | Application error code `0x0`, reason `normal closure`, is a normal close. |

### Transport selection by the client

The client races QUIC and WebSocket and keeps the first connection that succeeds. The
environment variable `NB_RELAY_TRANSPORT` changes this: `quic` or `ws` uses one
transport only, and `prefer-quic` or `prefer-ws` tries one first and falls back to the
other only if it fails to connect.

Because QUIC carries smaller messages than WebSocket, the client avoids QUIC in two
cases:

- When the WireGuard interface MTU is larger than 1280, the client does not dial QUIC.
- When a write is refused as too large for a datagram, the client closes the connection
  and avoids QUIC for that relay server for 10 minutes. The period grows on repeated
  failures, up to 60 minutes.

A relay can still receive a message on a WebSocket connection that is too large for the
destination's QUIC connection. The relay drops that one message and keeps both
connections up.

## Message format

All integers are big-endian. Every message starts with a two-byte header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | protocol version |
| 1 | 1 | message type |
| 2 | variable | body, which may be empty |

### Protocol version

The current protocol version is 1. Version 0 is invalid. The version is negotiated in the
handshake and applies to the whole connection; see [Version negotiation](#version-negotiation).

### Message types

| Value | Name | Direction | Body |
|---|---|---|---|
| 0 | Unknown | none | reserved |
| 1 | Hello | none | reserved; a removed handshake. The server rejects it. |
| 2 | HelloResponse | none | reserved; a removed handshake. |
| 3 | Transport | both | peer ID (36) + payload |
| 4 | Close | both | empty |
| 5 | HealthCheck | both | empty |
| 6 | Auth | client to server | magic (4) + peer ID (36) + token, layout below |
| 7 | AuthResponse | server to client | instance URL as UTF-8 bytes |
| 8 | SubscribePeerState | client to server | N peer IDs |
| 9 | UnsubscribePeerState | client to server | N peer IDs |
| 10 | PeersOnline | server to client | N peer IDs |
| 11 | PeersWentOffline | server to client | N peer IDs |

Values 1 and 2 must never be reused.

### Peer ID

A peer ID is 36 bytes: the ASCII prefix `sha-` (`73 68 61 2D`) followed by the SHA-256
digest of the peer's identifier. A NetBird client uses its WireGuard public key, as the
base64 text, as the identifier. The relay sees only the hashed form. In logs, a peer ID
is shown as `sha-` followed by the base64 encoding of the digest.

### Size limits

| Limit | Value | Applies to |
|---|---|---|
| `MaxHandshakeSize` | 8192 bytes | the first message on a connection (Auth) |
| `MaxHandshakeRespSize` | 8192 bytes | AuthResponse |
| `MaxMessageSize` | 8820 bytes | every other message on WebSocket |
| `QUICMaxDatagramSize` | 1188 bytes | every message on QUIC |

A Transport message carries at most `limit - 38` bytes of payload. Peer state messages
carry at most `(limit - 2) / 36` peer IDs: 244 on WebSocket and 32 on QUIC. Longer
lists are split across several messages by both the client and the server.

## Handshake

The first message a client sends after the transport connects is Auth. The server reads
at most 8192 bytes for it. The whole handshake, from accepting the connection to writing
the response, must finish within 10 seconds.

### Auth

Version 1 layout:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (1) |
| 1 | 1 | type (6) |
| 2 | 4 | magic `21 12 A4 42` |
| 6 | 36 | peer ID |
| 42 | variable | token: everything to the end of the message |

Layout for a client that advertises version 2 or higher:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | advertised version (2 or higher) |
| 1 | 1 | type (6) |
| 2 | 4 | magic `21 12 A4 42` |
| 6 | 36 | peer ID |
| 42 | 2 | token length L, 1 to 65535 |
| 44 | L | token |
| 44 + L | variable | extension area; a server that does not support it ignores it |

The server rejects the connection when the first message is not Auth, when the magic
value is wrong, when the message is too short, or when the token fails validation. A
rejected connection is closed without a response.

### Token

The protocol passes the token to the server's validator unchanged and does not define
its format. NetBird's validator expects this token, which the Management service issues
to clients and which the relay checks with a secret it shares with Management:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | algorithm: 1 = HMAC-SHA256 |
| 1 | 32 | HMAC-SHA256 of the payload, keyed with the shared secret |
| 33 | variable | payload: the expiry time as decimal Unix seconds in ASCII, at least 10 characters |

The token is accepted while the current time is not later than the expiry.

The relay's own HTTP health endpoint checks the WebSocket listener by connecting and
sending Auth with a peer ID built the same way from the string `healthcheck-agent`, and a
token in the correct format whose signature is all zeros.
The relay rejects that connection as it rejects any invalid token, and logs it at debug
level.

### AuthResponse

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | selected version |
| 1 | 1 | type (7) |
| 2 | variable | the server's instance URL, for example `rels://relay.example.com:443` |

The client stores the instance URL and shares it through Signal so that a remote peer
can connect to the same relay server. A client accepts AuthResponse only with a URL of
at least one byte.

### Version negotiation

The client advertises a version in the header of Auth. The server selects the lower of
the advertised version and the highest version it supports, and stamps that version on
AuthResponse and on every later message it sends on the connection, including forwarded
Transport messages. After the handshake, the server drops any inbound message whose
version is not the selected one; the connection stays up.

Current clients send Auth version 1 and accept only version 1 from the server.

## After the handshake

### Server handling of inbound messages

The server handles each inbound message by type:

| Type | Server action |
|---|---|
| Transport | Forward it; see [Forwarding](#forwarding). |
| HealthCheck | Record the health check reply. |
| Close | Close the connection. |
| SubscribePeerState | Register interest; answer with PeersOnline for the listed peers that are connected now. No answer when none are. |
| UnsubscribePeerState | Remove interest in the listed peers. |
| any other type, a second Auth, a wrong version, an unknown type | Drop the message and keep the connection. |

A read of zero bytes or a transport error ends the connection.

### Forwarding

For each Transport message from peer A addressed to peer B:

1. The server looks up B among the peers connected to this server.
2. If B is not connected, the server drops the message. It sends nothing back to A and
   does not keep the message.
3. Otherwise the server rewrites the message in place: byte 0 becomes B's selected
   version, and bytes 2 to 37 become A's peer ID. The payload is unchanged.
4. The server writes the message to B's connection. If the write fails, for example a
   message too large for B's QUIC datagram limit, the message is dropped and both
   connections stay up.

So the peer ID in a Transport message is the destination when a client sends it and the
source when a client receives it.

On WebSocket a write to B can wait up to 10 seconds, and while it waits the server reads
no further messages from A. On QUIC a write does not wait.

### Peer state notifications

A client subscribes to the peers it wants to reach through the relay and learns when
they connect and disconnect.

- After SubscribePeerState the server answers at once with PeersOnline for the listed
  peers that are connected.
- While the subscription lasts, the server sends PeersWentOffline each time a listed peer
  disconnects.
- The server sends PeersOnline for a listed peer that connects, once per subscription.
  To be told again, the client subscribes again.
- Notifications are queued per subscriber and sent in batches. When a peer changes state
  several times before a batch is sent, the subscriber receives the first change, and
  after it the opposite change only if the peer ended in the opposite state.

### Reconnecting with the same peer ID

When a peer connects with a peer ID that is already connected, the server closes the old
connection without a Close message and keeps the new one. Subscribers receive PeersOnline
for that peer, if they are owed one, and no PeersWentOffline.

### Close

Either side may send Close and then close the transport. There is no acknowledgement.
When the server shuts down, it sends Close to every peer, waits at most 3 seconds for
each write, and closes the connection.

## Health checks

Health checks are relay messages of type HealthCheck. They are separate from WebSocket
ping and pong and from QUIC keepalive.

| Setting | Value |
|---|---|
| Server sends HealthCheck every | 25 seconds |
| Server timeout window | 45 seconds (interval + 20 seconds) |
| Client timeout window | 35 seconds (interval + 10 seconds) |
| Missed windows before disconnect | 1, on both sides. `NB_RELAY_HC_ATTEMPT_THRESHOLD` changes it. |

- The server sends HealthCheck every 25 seconds. The client answers each one with a
  HealthCheck message.
- The server checks every 45 seconds whether a HealthCheck reply arrived since the last
  check. After the configured number of windows without one, it closes the connection.
  Only a HealthCheck reply counts; other messages from the peer do not.
- The client checks every 35 seconds whether a HealthCheck arrived from the server.
  After the configured number of windows without one, it closes the connection and
  reconnects.

## Keeping this in sync

This document describes behavior a peer can observe: bytes, sizes, timers and the
server's reaction to each message. A change to any of these must update this document in
the same pull request. The code that defines them is:

| Topic | Code |
|---|---|
| Message format, types, sizes, version negotiation | `shared/relay/messages/` |
| Size and path constants | `shared/relay/constants.go` |
| ALPN | `shared/relay/tls/alpn.go` |
| Health check timers and threshold | `shared/relay/healthcheck/` |
| Token format | `shared/relay/auth/hmac/v2/` |
| Handshake | `relay/server/handshake.go` |
| Inbound handling, forwarding, close | `relay/server/peer.go`, `relay/server/relay.go` |
| Peer state notifications | `relay/server/store/` |
| Listeners | `relay/server/listener/ws/`, `relay/server/listener/quic/` |
| Client transports and selection | `shared/relay/client/dialer/`, `shared/relay/client/transport.go`, `shared/relay/client/dialers_generic.go` |

Internal changes that a peer cannot observe, such as goroutine structure, locking or
metrics, do not need an update here.
