//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || netbsd || dragonfly

package systemops

import (
	"net"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// Shared, non-privileged routing test fixtures. The privileged TestRouting (and its
// per-platform init() appenders) consume these; they live here so the unprivileged
// BSD/darwin test files compile without the privileged build tag.

type PacketExpectation struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort int
	DstPort int
	UDP     bool
	TCP     bool
}

//nolint:unused // consumed by the privileged-tagged routing tests
type testCase struct {
	name              string
	expectedInterface string
	dialer            dialer
	expectedPacket    PacketExpectation
}

//nolint:unused // consumed by the privileged-tagged routing tests
var testCases = []testCase{
	{
		name:              "To external host without custom dialer via vpn",
		expectedInterface: expectedVPNint,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "192.0.2.1", 53),
	},
	{
		name:              "To external host with custom dialer via physical interface",
		expectedInterface: expectedExternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "192.0.2.1", 53),
	},

	{
		name:              "To duplicate internal route with custom dialer via physical interface",
		expectedInterface: expectedInternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},
	{
		name:              "To duplicate internal route without custom dialer via physical interface", // local route takes precedence
		expectedInterface: expectedInternalInt,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},

	{
		name:              "To unique vpn route with custom dialer via physical interface",
		expectedInterface: expectedExternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "172.16.0.2", 53),
	},
	{
		name:              "To unique vpn route without custom dialer via vpn",
		expectedInterface: expectedVPNint,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "172.16.0.2", 53),
	},
}

//nolint:unused // consumed by the privileged-tagged routing tests
func createPacketExpectation(srcIP string, srcPort int, dstIP string, dstPort int) PacketExpectation {
	return PacketExpectation{
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
		UDP:     true,
	}
}
