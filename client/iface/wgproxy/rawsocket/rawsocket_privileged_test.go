//go:build linux && !android && privileged

package rawsocket

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// The sender sockets must stay unmarked: a NAT rule matching on fwmark that
// rewrites the source of an injected packet makes WireGuard adopt the rewritten
// address as the peer endpoint.
func TestSenderRawSocketsCarryNoFwmark(t *testing.T) {
	// the mark is only ever applied when advanced routing is available, so
	// without it the assertion below would hold for the wrong reason
	nbnet.Init()
	if !nbnet.AdvancedRouting() {
		t.Skip("advanced routing unsupported, the sockets carry no mark either way")
	}

	tests := []struct {
		name    string
		prepare func() (net.PacketConn, error)
		// the proxy treats the IPv6 socket as optional, so a host without IPv6
		// is a reason to skip rather than to fail
		optional bool
	}{
		{name: "IPv4", prepare: PrepareSenderRawSocketIPv4},
		{name: "IPv6", prepare: PrepareSenderRawSocketIPv6, optional: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tc.prepare()
			if err != nil {
				if tc.optional {
					t.Skipf("prepare raw socket: %v", err)
				}
				t.Fatalf("prepare raw socket: %v", err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Logf("close raw socket: %v", err)
				}
			}()

			syscallConn, ok := conn.(syscall.Conn)
			if !ok {
				t.Fatalf("raw socket %T does not expose a syscall conn", conn)
			}
			raw, err := syscallConn.SyscallConn()
			if err != nil {
				t.Fatalf("syscall conn: %v", err)
			}

			var mark int
			var markErr error
			if err := raw.Control(func(fd uintptr) {
				mark, markErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
			}); err != nil {
				t.Fatalf("control: %v", err)
			}
			if markErr != nil {
				t.Fatalf("get SO_MARK: %v", markErr)
			}

			if mark != 0 {
				t.Errorf("SO_MARK = %#x, want 0", mark)
			}
		})
	}
}
