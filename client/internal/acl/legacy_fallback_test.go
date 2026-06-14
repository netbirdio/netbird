package acl

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	fwmgr "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// sourcesRecordingFirewall wraps a real firewall.Manager and records
// the source prefixes of every AddFilterRule call.
type sourcesRecordingFirewall struct {
	fwmgr.Manager
	mu      sync.Mutex
	sources [][]netip.Prefix
}

func (f *sourcesRecordingFirewall) AddFilterRule(id []byte, sources []netip.Prefix, destination fwmgr.Network, proto fwmgr.Protocol, sPort, dPort *fwmgr.Port, action fwmgr.Action) (fwmgr.Rule, error) {
	f.mu.Lock()
	f.sources = append(f.sources, sources)
	f.mu.Unlock()
	return f.Manager.AddFilterRule(id, sources, destination, proto, sPort, dPort, action)
}

// TestLegacyManagementFallbackUsesMatchAnySources verifies the
// allow-all fallback for old management servers (empty FirewallRules
// without the FirewallRulesIsEmpty flag) reaches the firewall as /0
// match-any sources. The fallback rule carries PeerIP 0.0.0.0; if that
// were converted to a host prefix (0.0.0.0/32) it would match nothing
// and all peer traffic would be dropped.
func TestLegacyManagementFallbackUsesMatchAnySources(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{IP: network.Addr(), Network: network}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	realFW, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() { require.NoError(t, realFW.Close(nil)) }()

	fw := &sourcesRecordingFirewall{Manager: realFW}
	acl := NewDefaultManager(fw)

	// Old management: no rules and no FirewallRulesIsEmpty flag.
	acl.ApplyFiltering(&mgmProto.NetworkMap{FirewallRules: nil, FirewallRulesIsEmpty: false}, false)

	fw.mu.Lock()
	defer fw.mu.Unlock()
	require.NotEmpty(t, fw.sources, "legacy fallback must install at least one allow-all rule")
	for _, sources := range fw.sources {
		require.NotEmpty(t, sources)
		for _, p := range sources {
			assert.Equal(t, 0, p.Bits(), "legacy fallback source %s must be a /0 match-any prefix", p)
		}
	}
}
