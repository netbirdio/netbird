package bind

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDualStackPacketConn_RoutesWritesToCorrectSocket(t *testing.T) {
	ipv4Conn := &mockPacketConn{network: "udp4"}
	ipv6Conn := &mockPacketConn{network: "udp6"}
	dualStack := NewDualStackPacketConn(ipv4Conn, ipv6Conn)

	tests := []struct {
		name       string
		addr       *net.UDPAddr
		wantSocket string
	}{
		{
			name:       "IPv4 address",
			addr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
			wantSocket: "udp4",
		},
		{
			name:       "IPv6 address",
			addr:       &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
			wantSocket: "udp6",
		},
		{
			name:       "IPv4-mapped IPv6 goes to IPv4",
			addr:       &net.UDPAddr{IP: net.ParseIP("::ffff:192.168.1.1"), Port: 1234},
			wantSocket: "udp4",
		},
		{
			name:       "IPv4 loopback",
			addr:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			wantSocket: "udp4",
		},
		{
			name:       "IPv6 loopback",
			addr:       &net.UDPAddr{IP: net.ParseIP("::1"), Port: 1234},
			wantSocket: "udp6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4Conn.writeCount = 0
			ipv6Conn.writeCount = 0

			n, err := dualStack.WriteTo([]byte("test"), tt.addr)
			require.NoError(t, err)
			assert.Equal(t, 4, n)

			if tt.wantSocket == "udp4" {
				assert.Equal(t, 1, ipv4Conn.writeCount, "expected write to IPv4")
				assert.Equal(t, 0, ipv6Conn.writeCount, "expected no write to IPv6")
			} else {
				assert.Equal(t, 0, ipv4Conn.writeCount, "expected no write to IPv4")
				assert.Equal(t, 1, ipv6Conn.writeCount, "expected write to IPv6")
			}
		})
	}
}

func TestDualStackPacketConn_IPv4OnlyRejectsIPv6(t *testing.T) {
	dualStack := NewDualStackPacketConn(&mockPacketConn{network: "udp4"}, nil)

	// IPv4 works
	_, err := dualStack.WriteTo([]byte("test"), &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234})
	require.NoError(t, err)

	// IPv6 fails
	_, err = dualStack.WriteTo([]byte("test"), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IPv6 connection")
}

func TestDualStackPacketConn_IPv6OnlyRejectsIPv4(t *testing.T) {
	dualStack := NewDualStackPacketConn(nil, &mockPacketConn{network: "udp6"})

	// IPv6 works
	_, err := dualStack.WriteTo([]byte("test"), &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234})
	require.NoError(t, err)

	// IPv4 fails
	_, err = dualStack.WriteTo([]byte("test"), &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IPv4 connection")
}

// TestDualStackPacketConn_ReadFromIsNotUsedInHotPath documents that ReadFrom
// only reads from one socket (IPv4 preferred). This is fine because the actual
// receive path uses wireguard-go's BatchReader directly, not ReadFrom.
func TestDualStackPacketConn_ReadFromIsNotUsedInHotPath(t *testing.T) {
	ipv4Conn := &mockPacketConn{
		network:  "udp4",
		readData: []byte("from ipv4"),
		readAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234},
	}
	ipv6Conn := &mockPacketConn{
		network:  "udp6",
		readData: []byte("from ipv6"),
		readAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234},
	}

	dualStack := NewDualStackPacketConn(ipv4Conn, ipv6Conn)

	buf := make([]byte, 100)
	n, addr, err := dualStack.ReadFrom(buf)

	require.NoError(t, err)
	// reads from IPv4 (preferred) - this is expected behavior
	assert.Equal(t, "from ipv4", string(buf[:n]))
	assert.Equal(t, "192.168.1.1", addr.(*net.UDPAddr).IP.String())
}

func TestDualStackPacketConn_LocalAddrPrefersIPv4(t *testing.T) {
	ipv4Addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 51820}
	ipv6Addr := &net.UDPAddr{IP: net.ParseIP("::"), Port: 51820}

	tests := []struct {
		name     string
		ipv4     net.PacketConn
		ipv6     net.PacketConn
		wantAddr net.Addr
	}{
		{
			name:     "both available returns IPv4",
			ipv4:     &mockPacketConn{localAddr: ipv4Addr},
			ipv6:     &mockPacketConn{localAddr: ipv6Addr},
			wantAddr: ipv4Addr,
		},
		{
			name:     "IPv4 only",
			ipv4:     &mockPacketConn{localAddr: ipv4Addr},
			ipv6:     nil,
			wantAddr: ipv4Addr,
		},
		{
			name:     "IPv6 only",
			ipv4:     nil,
			ipv6:     &mockPacketConn{localAddr: ipv6Addr},
			wantAddr: ipv6Addr,
		},
		{
			name:     "neither returns nil",
			ipv4:     nil,
			ipv6:     nil,
			wantAddr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dualStack := NewDualStackPacketConn(tt.ipv4, tt.ipv6)
			assert.Equal(t, tt.wantAddr, dualStack.LocalAddr())
		})
	}
}

// mock

type mockPacketConn struct {
	network    string
	writeCount int
	readData   []byte
	readAddr   net.Addr
	localAddr  net.Addr
}

func (m *mockPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if m.readData != nil {
		return copy(b, m.readData), m.readAddr, nil
	}
	return 0, nil, nil
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	m.writeCount++
	return len(b), nil
}

func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }
