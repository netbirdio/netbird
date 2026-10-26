package udpmux

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pion/transport/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingNet struct {
	transport.Net
	calls  atomic.Int64
	ifaces []*transport.Interface
}

func (n *countingNet) Interfaces() ([]*transport.Interface, error) {
	n.calls.Add(1)
	return n.ifaces, nil
}

func TestNewSingleSocketUDPMux_DoesNotDiscoverInterfaces(t *testing.T) {
	conn := listenUDP(t, net.IPv4zero)
	n := &countingNet{ifaces: []*transport.Interface{testInterface("eth0", net.IPv4(192, 168, 1, 10))}}

	mux := NewSingleSocketUDPMux(Params{UDPConn: conn, Net: n})
	t.Cleanup(func() { _ = mux.Close() })

	assert.Equal(t, int64(0), n.calls.Load(), "constructing the mux must not enumerate interfaces")

	addrs := mux.GetListenAddresses()
	assert.Equal(t, int64(1), n.calls.Load(), "listen addresses are discovered when they are asked for")

	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.Len(t, addrs, 1, "one address per discovered interface IP")
	assert.Equal(t, fmt.Sprintf("192.168.1.10:%d", port), addrs[0].String(), "the discovered IP is paired with the socket port")
}

func TestSingleSocketUDPMux_GetConnWithoutListenAddresses(t *testing.T) {
	t.Run("unspecified socket accepts any address", func(t *testing.T) {
		conn := listenUDP(t, net.IPv4zero)
		n := &countingNet{}
		mux := NewSingleSocketUDPMux(Params{UDPConn: conn, Net: n})
		t.Cleanup(func() { _ = mux.Close() })

		port := conn.LocalAddr().(*net.UDPAddr).Port
		pc, err := mux.GetConn("ufrag", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: port}, "candidate")
		require.NoError(t, err)
		assert.NotNil(t, pc, "a connection is created for a local address of an unspecified socket")
		assert.Equal(t, int64(0), n.calls.Load(), "GetConn must not depend on a prior discovery")
	})

	t.Run("specific socket rejects a foreign address", func(t *testing.T) {
		conn := listenUDP(t, net.IPv4(127, 0, 0, 1))
		mux := NewSingleSocketUDPMux(Params{UDPConn: conn})
		t.Cleanup(func() { _ = mux.Close() })

		_, err := mux.GetConn("ufrag", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 1234}, "candidate")
		assert.Error(t, err, "an address the socket is not bound to must be rejected")

		pc, err := mux.GetConn("ufrag", conn.LocalAddr(), "candidate")
		require.NoError(t, err)
		assert.NotNil(t, pc, "the bound address is accepted")
	})
}

func listenUDP(t *testing.T, ip net.IP) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func testInterface(name string, ip net.IP) *transport.Interface {
	ifc := transport.NewInterface(net.Interface{Index: 1, MTU: 1500, Name: name, Flags: net.FlagUp | net.FlagMulticast})
	ifc.AddAddress(&net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)})
	return ifc
}

func TestSingleSocketUDPMux_ConcurrentListenAddressesWithDefaultNet(t *testing.T) {
	conn := listenUDP(t, net.IPv4zero)
	mux := NewSingleSocketUDPMux(Params{UDPConn: conn})
	t.Cleanup(func() { _ = mux.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NotEmpty(t, mux.GetListenAddresses(), "every caller gets at least the socket address")
		}()
	}
	wg.Wait()
}
