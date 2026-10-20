//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetAccountSettings(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into accounts (id, settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
		 values('account-3',null,null,null,null,null,null,null,null,null,null,null)`)

	accountSettings, err := conn(t, ctx).GetAccountSettings(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, accountSettings, nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      true,
		PeerLoginExpiration:             86400000000000 * time.Nanosecond,
		PeerInactivityExpirationEnabled: false,
		PeerInactivityExpiration:        86400000000000 * time.Nanosecond,
		DNSDomain:                       "",
		IPv6EnabledGroups:               []string{"group-one-resource-id"},
		RoutingPeerDNSResolutionEnabled: false,
		LazyConnectionEnabled:           false,
		AutoUpdateVersion:               "disabled",
		AutoUpdateAlways:                false,
		MetricsPushEnabled:              false,
	})

	accountSettings, err = conn(t, ctx).GetAccountSettings(ctx, "account-2")
	assert.NoError(t, err)
	assert.Equal(t, accountSettings, nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      true,
		PeerLoginExpiration:             86400000000000 * time.Nanosecond,
		PeerInactivityExpirationEnabled: false,
		PeerInactivityExpiration:        86400000000000 * time.Nanosecond,
		DNSDomain:                       "",
		IPv6EnabledGroups:               []string{"group-two-resources-id"},
		RoutingPeerDNSResolutionEnabled: false,
		LazyConnectionEnabled:           false,
		AutoUpdateVersion:               "disabled",
		AutoUpdateAlways:                false,
		MetricsPushEnabled:              false,
	})

	accountSettings, err = conn(t, ctx).GetAccountSettings(ctx, "account-3")
	assert.NoError(t, err)
	assert.Equal(t, accountSettings, nmdata.AccountSettingsInfo{})
}
