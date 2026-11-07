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

// A STUN request sent on the new socket while the mux moves must keep its
// pending mapping: the swap and the invalidation happen as one step under the
// same lock sendSTUN takes.
func TestUpdateConnKeepsRequestsSentOnTheNewSocket(t *testing.T) {
	oldConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = oldConn.Close() })
	newConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = newConn.Close() })

	m := NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: oldConn})
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	oldAddr := m.LocalAddr()
	m.mu.Lock()
	done := make(chan struct{})
	go func() {
		m.UpdateConn(newConn)
		close(done)
	}()
	// While the mux lock is held, the socket must not move.
	end := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(end) {
		if m.LocalAddr().String() != oldAddr.String() {
			m.mu.Unlock()
			t.Fatal("UpdateConn swapped the socket without the mux lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	m.mu.Unlock()
	<-done

	_, err = m.sendSTUN(server)
	require.NoError(t, err)
	m.mu.Lock()
	_, pending := m.xorMappedMap[server.String()]
	m.mu.Unlock()
	assert.True(t, pending, "a request sent after the swap keeps its mapping")
}
