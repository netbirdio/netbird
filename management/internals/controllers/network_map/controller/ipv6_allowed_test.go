package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// The account-side builder (types.Account.peerIPv6AllowedSet) is the reference:
// an account with no IPv6-enabled group runs no IPv6 overlay at all, embedded
// proxy peers included — see TestPeerIPv6AllowedEmbeddedProxy. Both builders
// gate the same AAAA records, so the store-backed one has to agree.
func TestIPv6AllowedPeersFromData(t *testing.T) {
	data := func(enabledGroups []string) *networkmap.NetworkMapData {
		return &networkmap.NetworkMapData{
			AccountSettings: &nmdata.AccountSettingsInfo{IPv6EnabledGroups: enabledGroups},
			Peers: map[string]*nmdata.Peer{
				"peer1":  {ID: "peer1"},
				"lonely": {ID: "lonely"},
				"proxy":  {ID: "proxy", ProxyMeta: nmdata.ProxyMeta{Embedded: true, Cluster: "netbird.test"}},
			},
			Groups: map[string]*nmdata.Group{
				"group-devs": {ID: "group-devs", Peers: []string{"peer1"}},
			},
		}
	}

	t.Run("embedded proxy allowed when any v6 group exists, without group membership", func(t *testing.T) {
		allowed := IPv6AllowedPeersFromData(data([]string{"group-devs"}))
		assert.Contains(t, allowed, "proxy", "embedded proxy participates in v6 overlay")
		assert.Contains(t, allowed, "peer1", "regular peer in enabled group still allowed")
	})

	t.Run("embedded proxy denied when no v6 group enabled", func(t *testing.T) {
		allowed := IPv6AllowedPeersFromData(data(nil))
		assert.NotContains(t, allowed, "proxy", "v6 disabled account-wide denies embedded proxies too")
		assert.Empty(t, allowed, "no peer participates in the v6 overlay")
	})

	t.Run("non-embedded peer outside any enabled group is not pulled in", func(t *testing.T) {
		allowed := IPv6AllowedPeersFromData(data([]string{"group-devs"}))
		assert.NotContains(t, allowed, "lonely", "embedded-proxy bypass must not leak to regular peers")
	})
}
