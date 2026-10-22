package udpmux

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Server-reflexive addresses are learned through the socket and the network
// it sat on. After the socket moves to another network they are stale, and
// keeping them would hand ICE candidates of the old network for the cache TTL.
func TestUpdateConnDropsServerReflexiveMappings(t *testing.T) {
	oldConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = oldConn.Close() })
	newConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = newConn.Close() })

	m := NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: oldConn})
	pending := &xorMapped{waitAddrReceived: make(chan struct{}), expiresAt: time.Now().Add(time.Minute)}
	m.xorMappedMap["198.51.100.1:3478"] = pending

	m.UpdateConn(newConn)

	m.mu.Lock()
	left := len(m.xorMappedMap)
	m.mu.Unlock()
	assert.Zero(t, left, "mappings learned on the old network are dropped")
	select {
	case <-pending.waitAddrReceived:
	default:
		t.Fatal("a lookup waiting on the old mapping must be released")
	}
	assert.Equal(t, newConn.LocalAddr(), m.LocalAddr(), "the mux writes through the new socket")
}
