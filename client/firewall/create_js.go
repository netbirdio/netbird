//go:build js

package firewall

import (
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// NewFirewall returns a no-op firewall manager for the js/wasm build. The
// userspace firewall (uspfilter) pulls in github.com/google/gopacket (~450KB of
// protocol decoders) for packet filtering/NAT/conntrack, none of which is
// meaningful in the browser client — it tunnels through the netstack rather than
// filtering a real device. engine.go requires a non-nil Manager, so we satisfy
// the interface with a permissive no-op.
func NewFirewall(iface IFaceMapper, _ *statemanager.Manager, _ nftypes.FlowLogger, _ bool, _ uint16) (firewall.Manager, error) {
	return &noopFirewall{}, nil
}

// noopFirewall implements firewall.Manager doing nothing (allow-all).
type noopFirewall struct{}

func (noopFirewall) Init(*statemanager.Manager) error { return nil }
func (noopFirewall) AllowNetbird() error              { return nil }

func (noopFirewall) AddPeerFiltering(_ []byte, _ net.IP, _ firewall.Protocol, _ *firewall.Port, _ *firewall.Port, _ firewall.Action, _ string) ([]firewall.Rule, error) {
	return nil, nil
}
func (noopFirewall) DeletePeerRule(firewall.Rule) error { return nil }
func (noopFirewall) IsServerRouteSupported() bool       { return false }
func (noopFirewall) IsStateful() bool                   { return false }

func (noopFirewall) AddRouteFiltering(_ []byte, _ []netip.Prefix, _ firewall.Network, _ firewall.Protocol, _, _ *firewall.Port, _ firewall.Action) (firewall.Rule, error) {
	return nil, nil
}
func (noopFirewall) DeleteRouteRule(firewall.Rule) error        { return nil }
func (noopFirewall) AddNatRule(firewall.RouterPair) error       { return nil }
func (noopFirewall) RemoveNatRule(firewall.RouterPair) error    { return nil }
func (noopFirewall) SetLegacyManagement(bool) error             { return nil }
func (noopFirewall) Close(*statemanager.Manager) error          { return nil }
func (noopFirewall) Flush() error                               { return nil }
func (noopFirewall) SetLogLevel(log.Level)                      {}
func (noopFirewall) EnableRouting() error                       { return nil }
func (noopFirewall) DisableRouting() error                      { return nil }
func (noopFirewall) AddDNATRule(firewall.ForwardRule) (firewall.Rule, error) { return nil, nil }
func (noopFirewall) DeleteDNATRule(firewall.Rule) error         { return nil }
func (noopFirewall) UpdateSet(firewall.Set, []netip.Prefix) error { return nil }

func (noopFirewall) AddInboundDNAT(_ netip.Addr, _ firewall.Protocol, _, _ uint16) error {
	return nil
}
func (noopFirewall) RemoveInboundDNAT(_ netip.Addr, _ firewall.Protocol, _, _ uint16) error {
	return nil
}
func (noopFirewall) AddOutputDNAT(_ netip.Addr, _ firewall.Protocol, _, _ uint16) error {
	return nil
}
func (noopFirewall) RemoveOutputDNAT(_ netip.Addr, _ firewall.Protocol, _, _ uint16) error {
	return nil
}
func (noopFirewall) SetupEBPFProxyNoTrack(_, _ uint16) error { return nil }
