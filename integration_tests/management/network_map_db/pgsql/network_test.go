package networkmap_pgsql

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetNetwork(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	network, err := s.GetNetwork(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, network, nmdata.Network{
		Identifier: "network-1",
		Net:        mustParseCIDR("100.103.0.0/16"),
		NetV6:      mustParseCIDR("fdde:e995:fd38:a465::/64"),
		Serial:     1,
	})

	network, err = s.GetNetwork(ctx, "account-2")
	assert.NoError(t, err)
	assert.Equal(t, network, nmdata.Network{
		Identifier: "network-2",
		Net:        mustParseCIDR("110.0.0.0/16"),
		NetV6:      mustParseCIDR("fddf:e995:fd38:a465::/64"),
		Serial:     2,
	})
}

func mustParseCIDR(s string) net.IPNet {
	var toret net.IPNet

	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}

	jn, err := json.Marshal(net)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jn, &toret)
	if err != nil {
		panic(err)
	}

	return toret
}
