package relay

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startSTUNResponder answers every binding request with the sender's address as the
// XOR-MAPPED-ADDRESS, which is what a public STUN server reports back to a client.
func startSTUNResponder(t *testing.T) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := req.Decode(); err != nil || req.Type != stun.BindingRequest {
				continue
			}

			resp, err := stun.Build(
				stun.NewTransactionIDSetter(req.TransactionID),
				stun.BindingSuccess,
				&stun.XORMappedAddress{IP: from.IP, Port: from.Port},
				stun.Fingerprint,
			)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(resp.Raw, from)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr)
}

func TestProbeSTUN(t *testing.T) {
	serverAddr := startSTUNResponder(t)

	uri, err := stun.ParseURI("stun:" + net.JoinHostPort(serverAddr.IP.String(), strconv.Itoa(serverAddr.Port)))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr, err := NewStunTurnProbe(DefaultCacheTTL).probeSTUN(ctx, uri)
	require.NoError(t, err)

	mapped, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err, "probe should return a host:port address")
	assert.True(t, mapped.IP.Equal(serverAddr.IP), "mapped IP should be the loopback address the server saw")
	assert.NotZero(t, mapped.Port, "mapped port should be the client's source port")
}

func TestProbeSTUNUnreachable(t *testing.T) {
	// Grab a free port and release it so nothing answers there.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	deadAddr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())

	uri, err := stun.ParseURI("stun:" + deadAddr)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	addr, err := NewStunTurnProbe(DefaultCacheTTL).probeSTUN(ctx, uri)
	assert.Error(t, err, "probe against a silent server should fail")
	assert.Empty(t, addr, "no address should be reported on failure")
}
