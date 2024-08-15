package server

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/proto"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/stretchr/testify/assert"
)

// var peersUpdater *PeersUpdateManager

func TestCreateChannel(t *testing.T) {
	peer := "test-create"
	peersUpdater := NewPeersUpdateManager(nil)
	defer peersUpdater.CloseChannel(context.Background(), peer)

	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
}

func TestSendUpdate(t *testing.T) {
	peer := "test-sendupdate"
	peersUpdater := NewPeersUpdateManager(nil)
	update1 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 0,
		},
	}}
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.SendUpdate(context.Background(), peer, update1)
	select {
	case <-peersUpdater.peerChannels[peer]:
	default:
		t.Error("Update wasn't send")
	}

	for range [channelBufferSize]int{} {
		peersUpdater.SendUpdate(context.Background(), peer, update1)
	}

	update2 := &UpdateMessage{Update: &proto.SyncResponse{
		NetworkMap: &proto.NetworkMap{
			Serial: 10,
		},
	}}

	peersUpdater.SendUpdate(context.Background(), peer, update2)
	timeout := time.After(5 * time.Second)
	for range [channelBufferSize]int{} {
		select {
		case <-timeout:
			t.Error("timed out reading previously sent updates")
		case updateReader := <-peersUpdater.peerChannels[peer]:
			if updateReader.Update.NetworkMap.Serial == update2.Update.NetworkMap.Serial {
				t.Error("got the update that shouldn't have been sent")
			}
		}
	}

}

func TestCloseChannel(t *testing.T) {
	peer := "test-close"
	peersUpdater := NewPeersUpdateManager(nil)
	_ = peersUpdater.CreateChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; !ok {
		t.Error("Error creating the channel")
	}
	peersUpdater.CloseChannel(context.Background(), peer)
	if _, ok := peersUpdater.peerChannels[peer]; ok {
		t.Error("Error closing the channel")
	}
}

func TestHandlePeerMessageUpdate(t *testing.T) {
	tests := []struct {
		name           string
		peerID         string
		existingUpdate *UpdateMessage
		newUpdate      *UpdateMessage
		expectedResult bool
	}{
		{
			name:   "update message with turn credentials update",
			peerID: "peer",
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					WiretrusteeConfig: &proto.WiretrusteeConfig{},
				},
			},
			expectedResult: true,
		},
		{
			name:   "update message for peer without existing update",
			peerID: "peer1",
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
			},
			expectedResult: true,
		},
		{
			name:   "update message with no changes in update",
			peerID: "peer2",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			expectedResult: false,
		},
		{
			name:   "update message with changes in checks",
			peerID: "peer3",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
				Checks:     []*posture.Checks{},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 2},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
				Checks:     []*posture.Checks{{ID: "check1"}},
			},
			expectedResult: true,
		},
		{
			name:   "update message with lower serial number",
			peerID: "peer4",
			existingUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 2},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 2}},
			},
			newUpdate: &UpdateMessage{
				Update: &proto.SyncResponse{
					NetworkMap: &proto.NetworkMap{Serial: 1},
				},
				NetworkMap: &NetworkMap{Network: &Network{Serial: 1}},
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPeersUpdateManager(nil)
			ctx := context.Background()

			if tt.existingUpdate != nil {
				p.peerUpdateMessage[tt.peerID] = tt.existingUpdate
			}

			result := p.handlePeerMessageUpdate(ctx, tt.peerID, tt.newUpdate)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestIsNewPeerUpdateMessage(t *testing.T) {
	t.Run("Unchanged value", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.False(t, message)
	})

	t.Run("Unchanged value with serial incremented", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.False(t, message)
	})

	t.Run("Updating routes network", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.Routes[0].Network = netip.MustParsePrefix("1.1.1.1/32")
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)

	})

	t.Run("Updating routes groups", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.Routes[0].Groups = []string{"randomGroup1"}
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating network map peers", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newPeer := &nbpeer.Peer{
			IP:         net.ParseIP("192.168.1.4"),
			SSHEnabled: true,
			Key:        "peer4-key",
			DNSLabel:   "peer4",
			SSHKey:     "peer4-ssh-key",
		}
		newUpdateMessage2.NetworkMap.Peers = append(newUpdateMessage2.NetworkMap.Peers, newPeer)
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating posture checks", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newCheck := &posture.Checks{
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "10.0",
				},
			},
		}
		newUpdateMessage2.Checks = append(newUpdateMessage2.Checks, newCheck)
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating DNS configuration", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newDomain := "newexample.com"
		newUpdateMessage2.NetworkMap.DNSConfig.NameServerGroups[0].Domains = append(
			newUpdateMessage2.NetworkMap.DNSConfig.NameServerGroups[0].Domains,
			newDomain,
		)
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating peer IP", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.Peers[0].IP = net.ParseIP("192.168.1.10")
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating firewall rule", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.FirewallRules[0].Port = "443"
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Add new firewall rule", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newRule := &FirewallRule{
			PeerIP:    "192.168.1.3",
			Direction: firewallRuleDirectionOUT,
			Action:    string(PolicyTrafficActionDrop),
			Protocol:  string(PolicyRuleProtocolUDP),
			Port:      "53",
		}
		newUpdateMessage2.NetworkMap.FirewallRules = append(newUpdateMessage2.NetworkMap.FirewallRules, newRule)
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Removing nameserver", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.DNSConfig.NameServerGroups[0].NameServers = make([]nbdns.NameServer, 0)
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating name server IP", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.DNSConfig.NameServerGroups[0].NameServers[0].IP = netip.MustParseAddr("8.8.4.4")
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

	t.Run("Updating custom DNS zone", func(t *testing.T) {
		newUpdateMessage1 := createMockUpdateMessage(t)
		newUpdateMessage2 := createMockUpdateMessage(t)

		newUpdateMessage2.NetworkMap.DNSConfig.CustomZones[0].Records[0].RData = "100.64.0.2"
		newUpdateMessage2.Update.NetworkMap.Serial++

		message, err := isNewPeerUpdateMessage(newUpdateMessage1, newUpdateMessage2)
		assert.NoError(t, err)
		assert.True(t, message)
	})

}

func createMockUpdateMessage(t *testing.T) *UpdateMessage {
	t.Helper()

	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	domainList, err := domain.FromStringList([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		Signal: &Host{
			Proto:    "https",
			URI:      "signal.uri",
			Username: "",
			Password: "",
		},
		Stuns: []*Host{{URI: "stun.uri", Proto: UDP}},
		TURNConfig: &TURNConfig{
			Turns: []*Host{{URI: "turn.uri", Proto: UDP, Username: "turn-user", Password: "turn-pass"}},
		},
	}
	peer := &nbpeer.Peer{
		IP:         net.ParseIP("192.168.1.1"),
		SSHEnabled: true,
		Key:        "peer-key",
		DNSLabel:   "peer1",
		SSHKey:     "peer1-ssh-key",
	}
	turnCredentials := &TURNCredentials{
		Username: "turn-user",
		Password: "turn-pass",
	}
	networkMap := &NetworkMap{
		Network:      &Network{Net: *ipNet, Serial: 1000},
		Peers:        []*nbpeer.Peer{{IP: net.ParseIP("192.168.1.2"), Key: "peer2-key", DNSLabel: "peer2", SSHEnabled: true, SSHKey: "peer2-ssh-key"}},
		OfflinePeers: []*nbpeer.Peer{{IP: net.ParseIP("192.168.1.3"), Key: "peer3-key", DNSLabel: "peer3", SSHEnabled: true, SSHKey: "peer3-ssh-key"}},
		Routes: []*nbroute.Route{
			{
				ID:          "route1",
				Network:     netip.MustParsePrefix("10.0.0.0/24"),
				KeepRoute:   true,
				NetID:       "route1",
				Peer:        "peer1",
				NetworkType: 1,
				Masquerade:  true,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{"test1", "test2"},
			},
			{
				ID:          "route2",
				Domains:     domainList,
				KeepRoute:   true,
				NetID:       "route2",
				Peer:        "peer1",
				NetworkType: 1,
				Masquerade:  true,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{"test1", "test2"},
			},
		},
		DNSConfig: nbdns.Config{
			ServiceEnable: true,
			NameServerGroups: []*nbdns.NameServerGroup{
				{
					NameServers: []nbdns.NameServer{{
						IP:     netip.MustParseAddr("8.8.8.8"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					}},
					Primary:              true,
					Domains:              []string{"example.com"},
					Enabled:              true,
					SearchDomainsEnabled: true,
				},
				{
					ID: "ns1",
					NameServers: []nbdns.NameServer{{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					}},
					Groups:               []string{"group1"},
					Primary:              true,
					Domains:              []string{"example.com"},
					Enabled:              true,
					SearchDomainsEnabled: true,
				},
			},
			CustomZones: []nbdns.CustomZone{{Domain: "example.com", Records: []nbdns.SimpleRecord{{Name: "example.com", Type: 1, Class: "IN", TTL: 60, RData: "100.64.0.1"}}}},
		},
		FirewallRules: []*FirewallRule{
			{PeerIP: "192.168.1.2", Direction: firewallRuleDirectionIN, Action: string(PolicyTrafficActionAccept), Protocol: string(PolicyRuleProtocolTCP), Port: "80"},
		},
	}
	dnsName := "example.com"
	checks := []*posture.Checks{
		{
			Checks: posture.ChecksDefinition{
				ProcessCheck: &posture.ProcessCheck{
					Processes: []posture.Process{{LinuxPath: "/usr/bin/netbird"}},
				},
			},
		},
	}
	dnsCache := &DNSConfigCache{}

	return &UpdateMessage{
		Update:     toSyncResponse(context.Background(), config, peer, turnCredentials, networkMap, dnsName, checks, dnsCache),
		NetworkMap: networkMap,
		Checks:     checks,
	}
}
