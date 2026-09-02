//go:build integration

package networkmap_pgsql

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetPeers(t *testing.T) {
	ctx := context.TODO()

	peers, clusterToPeersIdx, err := conn(t, ctx).GetPeers(ctx, "account-1")
	assert.NoError(t, err)

	// shouldn't be returned in the index, as it's not connected
	execQuery(t, ctx,
		`insert into peers (id,account_id,"key",ssh_key,proxy_meta_embedded,peer_status_connected)
		 values('peer-4','account-1','key-4','ssh-key-4',true,false)`)
	// shouldn't be returned in the index as it doesn't have cluster set
	execQuery(t, ctx,
		`insert into peers (id,account_id,"key",ssh_key,proxy_meta_embedded,peer_status_connected)
		 values('peer-5','account-1','key-5','ssh-key-5',false,true)`)

	peer1 := nmdata.Peer{
		ID:                     "peer-id-1",
		Key:                    "key-1",
		SSHKey:                 "ssh-key-1",
		DNSLabel:               "peer-1",
		ExtraDNSLabels:         []string{"extra-peer-1"},
		UserID:                 "user-id-1",
		SSHEnabled:             true,
		LoginExpirationEnabled: true,
		LastLogin:              mustParseTime("2026-08-06T13:25:59.12999+00:00"),
		IP:                     netip.MustParseAddr("10.10.10.1"),
		IPv6:                   netip.MustParseAddr("fdf4:ba80:6aa5:89f1:44d7:8701:8699:4940"),
		RequiresApproval:       false,
		Connected:              true,
		Meta: nmdata.PeerSystemMeta{
			WtVersion:     "0.76.0",
			GoOS:          "linux",
			OSVersion:     "26.4.1",
			KernelVersion: "6.8.0-134-generic",
			NetworkAddresses: []nmdata.NetworkAddress{
				{NetIP: netip.MustParsePrefix("fe80::8b4c:973f:a76b:3771/64")},
				{NetIP: netip.MustParsePrefix("192.168.16.1/20")},
			},
			Files: []nmdata.File{
				{Path: "/usr/bin/netbird", ProcessIsRunning: false},
			},
			Capabilities: []int32{1, 2},
			Flags: nmdata.Flags{
				ServerSSHAllowed: true,
				DisableIPv6:      false,
			},
			SyncMessageVersion: 1,
		},
		ProxyMeta: nmdata.ProxyMeta{
			Embedded: true,
			Cluster:  "cluster-1.netbird.services",
		},
		Location: nmdata.PeerLocation{
			CountryCode:  "DE",
			CityName:     "Berlin",
			ConnectionIP: net.ParseIP("46.201.148.187"),
		},
	}
	peer2 := nmdata.Peer{
		ID:                     "peer-id-2",
		Key:                    "key-2",
		SSHKey:                 "ssh-key-2",
		DNSLabel:               "peer-2",
		ExtraDNSLabels:         []string{"extra-peer-2"},
		UserID:                 "user-id-2",
		SSHEnabled:             true,
		LoginExpirationEnabled: true,
		LastLogin:              mustParseTime("2026-08-06T14:25:59.12999+00:00"),
		IP:                     netip.MustParseAddr("10.10.100.1"),
		IPv6:                   netip.MustParseAddr("fdf5:ba80:6aa5:89f1:44d7:8701:8699:4940"),
		RequiresApproval:       false,
		Connected:              true,
		Meta: nmdata.PeerSystemMeta{
			WtVersion:     "0.76.1",
			GoOS:          "linux",
			OSVersion:     "26.4.2",
			KernelVersion: "6.8.0-135-generic",
			NetworkAddresses: []nmdata.NetworkAddress{
				{NetIP: netip.MustParsePrefix("fe81::8b4c:973f:a76b:3771/64")},
				{NetIP: netip.MustParsePrefix("192.168.17.1/20")},
			},
			Files: []nmdata.File{
				{Path: "/usr/bin/netbird", ProcessIsRunning: false},
			},
			Capabilities: []int32{1, 2},
			Flags: nmdata.Flags{
				ServerSSHAllowed: true,
				DisableIPv6:      false,
			},
			SyncMessageVersion: 0,
		},
		ProxyMeta: nmdata.ProxyMeta{
			Embedded: true,
			Cluster:  "cluster-2.netbird.services",
		},
		Location: nmdata.PeerLocation{
			CountryCode:  "DE",
			CityName:     "Berlin",
			ConnectionIP: net.ParseIP("46.201.149.187"),
		},
	}
	peer3 := nmdata.Peer{
		ID:                     "peer-id-3",
		Key:                    "key-3",
		SSHKey:                 "ssh-key-3",
		DNSLabel:               "peer-3",
		ExtraDNSLabels:         []string{"extra-peer-3"},
		UserID:                 "user-id-3",
		SSHEnabled:             true,
		LoginExpirationEnabled: true,
		LastLogin:              mustParseTime("2026-08-06T12:25:59.12999+00:00"),
		IP:                     netip.MustParseAddr("10.10.200.1"),
		IPv6:                   netip.MustParseAddr("fdf6:ba80:6aa5:89f1:44d7:8701:8699:4940"),
		RequiresApproval:       false,
		Connected:              true,
		Meta: nmdata.PeerSystemMeta{
			WtVersion:     "0.76.2",
			GoOS:          "linux",
			OSVersion:     "26.4.3",
			KernelVersion: "6.8.0-136-generic",
			NetworkAddresses: []nmdata.NetworkAddress{
				{NetIP: netip.MustParsePrefix("fe82::8b4c:973f:a76b:3771/64")},
				{NetIP: netip.MustParsePrefix("192.168.18.1/20")},
			},
			Files: []nmdata.File{
				{Path: "/usr/bin/netbird", ProcessIsRunning: false},
			},
			Capabilities: []int32{1, 2},
			Flags: nmdata.Flags{
				ServerSSHAllowed: true,
				DisableIPv6:      false,
			},
			SyncMessageVersion: 1,
		},
		ProxyMeta: nmdata.ProxyMeta{
			Embedded: true,
			Cluster:  "cluster-3.netbird.services",
		},
		Location: nmdata.PeerLocation{
			CountryCode:  "DE",
			CityName:     "Berlin",
			ConnectionIP: net.ParseIP("46.201.150.187"),
		},
	}

	assert.Contains(t, peers, peer1)
	assert.Contains(t, peers, peer2)
	assert.Contains(t, peers, peer3)

	assert.Equal(t, clusterToPeersIdx, map[string][]*nmdata.Peer{
		"cluster-1.netbird.services": {&peer1},
		"cluster-2.netbird.services": {&peer2},
		"cluster-3.netbird.services": {&peer3},
	})
}
