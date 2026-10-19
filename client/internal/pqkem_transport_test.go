package internal

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pqInbound struct {
	src netip.AddrPort
	msg []byte
}

func runPQTransport(t *testing.T, tr *pqTransport) <-chan pqInbound {
	t.Helper()
	got := make(chan pqInbound, 1)
	tr.Run(func(src netip.AddrPort, msg []byte) {
		select {
		case got <- pqInbound{src: src, msg: msg}:
		default:
		}
	})
	t.Cleanup(func() { _ = tr.Close() })
	return got
}

func receivePQ(t *testing.T, got <-chan pqInbound) pqInbound {
	t.Helper()
	select {
	case in := <-got:
		return in
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram received")
		return pqInbound{}
	}
}

// TestPQTransport_HostRoundTrip sends a datagram between two host-bound transports. The
// second bind collides with the first on DefaultPort, so it also covers the fallback to
// an ephemeral port. The source must come back as a plain (unmapped) IPv4 endpoint,
// since the manager matches it against registered peer endpoints.
func TestPQTransport_HostRoundTrip(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")

	a, err := newPQTransport(loopback)
	require.NoError(t, err)
	b, err := newPQTransport(loopback)
	require.NoError(t, err)
	require.NotEqual(t, a.LocalPort(), b.LocalPort(), "two transports on one IP must get distinct ports")

	runPQTransport(t, a)
	gotB := runPQTransport(t, b)

	require.NoError(t, a.Send(netip.AddrPortFrom(loopback, uint16(b.LocalPort())), []byte("offer")))

	in := receivePQ(t, gotB)
	assert.Equal(t, []byte("offer"), in.msg, "payload must arrive intact")
	assert.Equal(t, netip.AddrPortFrom(loopback, uint16(a.LocalPort())), in.src, "source must be the sender's unmapped IPv4 endpoint")
}
