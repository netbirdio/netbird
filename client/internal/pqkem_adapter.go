package internal

import "github.com/netbirdio/netbird/client/internal/pqkem"

// No-op adapters wiring the engine to the ML-KEM manager's two seams. They are
// placeholders so the manager can be instantiated and its lifecycle managed while
// the real integration is built.
//
// TODO(NET-1406):
//   - noopPQTransport -> real tunnel-UDP transport (send over the WG data path,
//     feed inbound to Manager.OnDataPathMessage), analogue of go-rosenpass's Conn.
//   - noopPQCallbackHandler -> program the derived PSK via iface/wgctrl on
//     OnNewPSKReady, and tear the peer down / trigger ICE reconnect on OnRekeyFailed.

type noopPQTransport struct{}

func (noopPQTransport) SendDataPath(remoteID string, msg []byte) error { return nil }

type noopPQCallbackHandler struct{}

func (noopPQCallbackHandler) OnNewPSKReady(remoteID string, psk pqkem.PSK) error { return nil }

func (noopPQCallbackHandler) OnRekeyFailed(remoteID string) error { return nil }
