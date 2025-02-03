package peer

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/util"
)

// FQDNOld is the original implementation for benchmarking purposes
func (p *Peer) FQDNOld(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", p.DNSLabel, dnsDomain)
}

func BenchmarkFQDN(b *testing.B) {
	p := &Peer{DNSLabel: "test-peer"}
	dnsDomain := "example.com"

	b.Run("Old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.FQDNOld(dnsDomain)
		}
	})

	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.FQDN(dnsDomain)
		}
	})
}

func TestIsEqual(t *testing.T) {
	meta1 := PeerSystemMeta{
		NetworkAddresses: []NetworkAddress{{
			NetIP: netip.MustParsePrefix("192.168.1.2/24"),
			Mac:   "2",
		},
			{
				NetIP: netip.MustParsePrefix("192.168.1.0/24"),
				Mac:   "1",
			},
		},
		Files: []File{
			{
				Path:             "/etc/hosts1",
				Exist:            true,
				ProcessIsRunning: true,
			},
			{
				Path:             "/etc/hosts2",
				Exist:            false,
				ProcessIsRunning: false,
			},
		},
	}
	meta2 := PeerSystemMeta{
		NetworkAddresses: []NetworkAddress{
			{
				NetIP: netip.MustParsePrefix("192.168.1.0/24"),
				Mac:   "1",
			},
			{
				NetIP: netip.MustParsePrefix("192.168.1.2/24"),
				Mac:   "2",
			},
		},
		Files: []File{
			{
				Path:             "/etc/hosts2",
				Exist:            false,
				ProcessIsRunning: false,
			},
			{
				Path:             "/etc/hosts1",
				Exist:            true,
				ProcessIsRunning: true,
			},
		},
	}
	if !meta1.isEqual(meta2) {
		t.Error("meta1 should be equal to meta2")
	}
}

func Test_EqualPeersWithSameAttributesReturnsTrue(t *testing.T) {
	peer1 := &Peer{
		ID: "peer1", AccountID: "account1", Key: "key1", IP: net.ParseIP("192.168.1.1"),
		Meta: PeerSystemMeta{Hostname: "host1"}, Name: "peer1", DNSLabel: "peer1",
		Status: &PeerStatus{Connected: true}, UserID: "user1", SSHKey: "sshkey1",
		SSHEnabled: true, LoginExpirationEnabled: true, LastLogin: util.ToPtr(time.Now()),
		CreatedAt: time.Now(), Ephemeral: true, Location: Location{CityName: "City1"},
	}
	peer2 := &Peer{
		ID: "peer1", AccountID: "account1", Key: "key1", IP: net.ParseIP("192.168.1.1"),
		Meta: PeerSystemMeta{Hostname: "host1"}, Name: "peer1", DNSLabel: "peer1",
		Status: &PeerStatus{Connected: true}, UserID: "user1", SSHKey: "sshkey1",
		SSHEnabled: true, LoginExpirationEnabled: true, LastLogin: util.ToPtr(time.Now()),
		CreatedAt: time.Now(), Ephemeral: true, Location: Location{CityName: "City1"},
	}

	assert.True(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentIDsReturnsFalse(t *testing.T) {
	peer1 := &Peer{ID: "peer1"}
	peer2 := &Peer{ID: "peer2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentAccountIDsReturnsFalse(t *testing.T) {
	peer1 := &Peer{AccountID: "account1"}
	peer2 := &Peer{AccountID: "account2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentKeysReturnsFalse(t *testing.T) {
	peer1 := &Peer{Key: "key1"}
	peer2 := &Peer{Key: "key2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentIPsReturnsFalse(t *testing.T) {
	peer1 := &Peer{IP: net.ParseIP("192.168.1.1")}
	peer2 := &Peer{IP: net.ParseIP("192.168.1.2")}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentMetaReturnsFalse(t *testing.T) {
	peer1 := &Peer{Meta: PeerSystemMeta{Hostname: "host1"}}
	peer2 := &Peer{Meta: PeerSystemMeta{Hostname: "host2"}}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentNamesReturnsFalse(t *testing.T) {
	peer1 := &Peer{Name: "peer1"}
	peer2 := &Peer{Name: "peer2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentDNSLabelsReturnsFalse(t *testing.T) {
	peer1 := &Peer{DNSLabel: "peer1"}
	peer2 := &Peer{DNSLabel: "peer2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentStatusesReturnsFalse(t *testing.T) {
	peer1 := &Peer{Status: &PeerStatus{Connected: true}}
	peer2 := &Peer{Status: &PeerStatus{Connected: false}}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentUserIDsReturnsFalse(t *testing.T) {
	peer1 := &Peer{UserID: "user1"}
	peer2 := &Peer{UserID: "user2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentSSHKeysReturnsFalse(t *testing.T) {
	peer1 := &Peer{SSHKey: "sshkey1"}
	peer2 := &Peer{SSHKey: "sshkey2"}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentSSHEnabledReturnsFalse(t *testing.T) {
	peer1 := &Peer{SSHEnabled: true}
	peer2 := &Peer{SSHEnabled: false}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentLoginExpirationEnabledReturnsFalse(t *testing.T) {
	peer1 := &Peer{LoginExpirationEnabled: true}
	peer2 := &Peer{LoginExpirationEnabled: false}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentLastLoginReturnsFalse(t *testing.T) {
	now := time.Now()
	peer1 := &Peer{LastLogin: &now}
	peer2 := &Peer{LastLogin: util.ToPtr(now.Add(time.Hour))}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentCreatedAtReturnsFalse(t *testing.T) {
	now := time.Now()
	peer1 := &Peer{CreatedAt: now}
	peer2 := &Peer{CreatedAt: now.Add(time.Hour)}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentEphemeralReturnsFalse(t *testing.T) {
	peer1 := &Peer{Ephemeral: true}
	peer2 := &Peer{Ephemeral: false}

	assert.False(t, peer1.Equal(peer2))
}

func Test_EqualPeersWithDifferentLocationsReturnsFalse(t *testing.T) {
	peer1 := &Peer{Location: Location{CityName: "City1"}}
	peer2 := &Peer{Location: Location{CityName: "City2"}}

	assert.False(t, peer1.Equal(peer2))
}
