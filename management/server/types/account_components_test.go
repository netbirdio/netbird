package types

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestFilterDNSRecordsByPeersExcludesDisconnectedPeers(t *testing.T) {
	connected := &nbpeer.Peer{
		IP:     netip.MustParseAddr("100.64.0.1"),
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
	}
	disconnected := &nbpeer.Peer{
		IP:     netip.MustParseAddr("100.64.0.2"),
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
	}
	records := []nbdns.SimpleRecord{
		{Name: "connected.example", RData: connected.IP.String()},
		{Name: "disconnected.example", RData: disconnected.IP.String()},
	}

	got := filterDNSRecordsByPeers(records, map[string]*nbpeer.Peer{
		"connected":    connected,
		"disconnected": disconnected,
	}, false)

	assert.Equal(t, []nbdns.SimpleRecord{records[0]}, got)
}
