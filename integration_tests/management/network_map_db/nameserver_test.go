//go:build integration

package networkmap_pgsql

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetNameServerGroups(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into name_server_groups (id, public_id, name, description, name_servers, groups, domains, enabled, search_domains_enabled, "primary", account_id)
		VALUES('nsgroup-1','nsgroup-1-public','nsgroup-1','nsgroup-1','[{"IP":"192.168.31.2","NSType":1,"Port":53}]','["group-one-resource-id"]','["test-1.com"]',TRUE,FALSE,TRUE,'account-1')`)
	execQuery(t, ctx,
		`insert into name_server_groups (id, public_id, name, description, name_servers, groups, domains, enabled, search_domains_enabled,"primary",account_id)
		VALUES('nsgroup-2','nsgroup-2-public','nsgroup-2','nsgroup-2','[{"IP":"192.168.32.3","NSType":1,"Port":53}]','["group-one-resource-id","group-no-resources-id"]','["test-1.com","test-2.com"]',TRUE,FALSE,TRUE,'account-1')`)
	execQuery(t, ctx,
		`insert into name_server_groups (id, public_id, name, description, name_servers, groups, domains, enabled, search_domains_enabled,"primary",account_id)
		VALUES('nsgroup-3','nsgroup-3-public',null,null,null,null,null,TRUE,FALSE,FALSE,'account-1')`)

	nsgroups, err := conn(t, ctx).GetNameServerGroups(ctx, "account-1")
	assert.NoError(t, err)

	assert.Contains(t, nsgroups, nmdata.NameServerGroup{
		ID:                   "nsgroup-1",
		PublicID:             "nsgroup-1-public",
		Name:                 "nsgroup-1",
		Description:          "nsgroup-1",
		NameServers:          []nmdata.NameServer{{IP: netip.MustParseAddr("192.168.31.2"), NSType: 1, Port: 53}},
		Groups:               []string{"group-one-resource-id"},
		Domains:              []string{"test-1.com"},
		Primary:              true,
		SearchDomainsEnabled: false,
		Enabled:              true,
	})
	assert.Contains(t, nsgroups, nmdata.NameServerGroup{
		ID:                   "nsgroup-2",
		PublicID:             "nsgroup-2-public",
		Name:                 "nsgroup-2",
		Description:          "nsgroup-2",
		NameServers:          []nmdata.NameServer{{IP: netip.MustParseAddr("192.168.32.3"), NSType: 1, Port: 53}},
		Groups:               []string{"group-one-resource-id", "group-no-resources-id"},
		Domains:              []string{"test-1.com", "test-2.com"},
		Primary:              true,
		SearchDomainsEnabled: false,
		Enabled:              true,
	})
	assert.Contains(t, nsgroups, nmdata.NameServerGroup{
		ID:                   "nsgroup-3",
		PublicID:             "nsgroup-3-public",
		Primary:              false,
		SearchDomainsEnabled: false,
		Enabled:              true,
	})
}
