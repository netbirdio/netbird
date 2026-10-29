package peerid

import (
	"crypto/sha256"

	v2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

var (
	// HealthCheckPeerID is the hashed peer ID for health check connections
	HealthCheckPeerID = messages.HashID("healthcheck-agent")

	// DummyAuthToken is a structurally valid auth token for health check.
	// The signature is not valid but the format is correct (1 byte algo + 32 bytes signature + payload).
	DummyAuthToken = createDummyToken()
)

func createDummyToken() []byte {
	token := v2.Token{
		AuthAlgo:  v2.AuthAlgoHMACSHA256,
		Signature: make([]byte, sha256.Size),
		Payload:   []byte("healthcheck"),
	}
	return token.Marshal()
}

// IsHealthCheck checks if the given peer ID is the health check agent
func IsHealthCheck(peerID *messages.PeerID) bool {
	return peerID != nil && *peerID == HealthCheckPeerID
}
