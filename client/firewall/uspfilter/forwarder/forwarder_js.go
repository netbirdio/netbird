//go:build js

package forwarder

import (
	"errors"
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// PacketCapture captures raw packets for debugging. Implementations must be
// safe for concurrent use and must not block.
type PacketCapture interface {
	Offer(data []byte, outbound bool)
}

// Forwarder is a no-op stub for the js/wasm build. The userspace-firewall packet
// forwarder relies on the gvisor netstack, which is not compiled for the browser
// client (it uses the lneto netstack + websocket transport).
type Forwarder struct{}

// New always fails under wasm so the firewall cleanly disables forwarding
// (see filter.go: a New error sets routingEnabled=false and leaves forwarder nil).
func New(iface common.IFaceMapper, logger *nblog.Logger, flowLogger nftypes.FlowLogger, netstack bool, mtu uint16) (*Forwarder, error) {
	return nil, errors.New("packet forwarding not supported under wasm")
}

func (f *Forwarder) SetCapture(pc PacketCapture) {}

func (f *Forwarder) InjectIncomingPacket(payload []byte) error {
	return errors.New("packet forwarding not supported under wasm")
}

func (f *Forwarder) Stop() {}

func (f *Forwarder) RegisterRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, ruleID []byte) {}

func (f *Forwarder) DeleteRuleID(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) {}
