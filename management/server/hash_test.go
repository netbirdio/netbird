package server

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/mitchellh/hashstructure/v2"
	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	route2 "github.com/netbirdio/netbird/route"
	"github.com/r3labs/diff"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func initTestAccount(b *testing.B, numPerAccount int) *Account {
	b.Helper()

	account := newAccountWithId("account_id", "testuser", "")
	groupALL, err := account.GetGroupAll()
	if err != nil {
		b.Fatal(err)
	}
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	for n := 0; n < numPerAccount; n++ {
		netIP := randomIPv4()
		peerID := fmt.Sprintf("%s-peer-%d", account.Id, n)

		peer := &nbpeer.Peer{
			ID:         peerID,
			Key:        peerID,
			SetupKey:   "",
			IP:         netIP,
			Name:       peerID,
			DNSLabel:   peerID,
			UserID:     userID,
			Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
			SSHEnabled: false,
		}
		account.Peers[peerID] = peer
		group, _ := account.GetGroupAll()
		group.Peers = append(group.Peers, peerID)
		user := &User{
			Id:        fmt.Sprintf("%s-user-%d", account.Id, n),
			AccountID: account.Id,
		}
		account.Users[user.Id] = user
		route := &route2.Route{
			ID:          route2.ID(fmt.Sprintf("network-id-%d", n)),
			Description: "base route",
			NetID:       route2.NetID(fmt.Sprintf("network-id-%d", n)),
			Network:     netip.MustParsePrefix(netIP.String() + "/24"),
			NetworkType: route2.IPv4Network,
			Metric:      9999,
			Masquerade:  false,
			Enabled:     true,
			Groups:      []string{groupALL.ID},
		}
		account.Routes[route.ID] = route

		group = &nbgroup.Group{
			ID:        fmt.Sprintf("group-id-%d", n),
			AccountID: account.Id,
			Name:      fmt.Sprintf("group-id-%d", n),
			Issued:    "api",
			Peers:     nil,
		}
		account.Groups[group.ID] = group

		nameserver := &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("nameserver-id-%d", n),
			AccountID:            account.Id,
			Name:                 fmt.Sprintf("nameserver-id-%d", n),
			Description:          "",
			NameServers:          []nbdns.NameServer{{IP: netip.MustParseAddr(netIP.String()), NSType: nbdns.UDPNameServerType}},
			Groups:               []string{group.ID},
			Primary:              false,
			Domains:              nil,
			Enabled:              false,
			SearchDomainsEnabled: false,
		}
		account.NameServerGroups[nameserver.ID] = nameserver

		setupKey := GenerateDefaultSetupKey()
		account.SetupKeys[setupKey.Key] = setupKey
	}

	group := &nbgroup.Group{
		ID:        "randomID",
		AccountID: account.Id,
		Name:      "randomName",
		Issued:    "api",
		Peers:     groupALL.Peers[:numPerAccount-1],
	}
	account.Groups[group.ID] = group

	account.Policies = []*Policy{
		{
			ID:          "RuleDefault",
			Name:        "Default",
			Description: "This is a default rule that allows connections between all the resources",
			Enabled:     true,
			Rules: []*PolicyRule{
				{
					ID:            "RuleDefault",
					Name:          "Default",
					Description:   "This is a default rule that allows connections between all the resources",
					Bidirectional: true,
					Enabled:       true,
					Protocol:      PolicyRuleProtocolTCP,
					Action:        PolicyTrafficActionAccept,
					Sources: []string{
						group.ID,
					},
					Destinations: []string{
						group.ID,
					},
				},
				{
					ID:            "RuleDefault2",
					Name:          "Default",
					Description:   "This is a default rule that allows connections between all the resources",
					Bidirectional: true,
					Enabled:       true,
					Protocol:      PolicyRuleProtocolUDP,
					Action:        PolicyTrafficActionAccept,
					Sources: []string{
						groupALL.ID,
					},
					Destinations: []string{
						groupALL.ID,
					},
				},
			},
		},
	}
	return account
}

// 1000 - 6717416375 ns/op
// 500 -  1732888875 ns/op
func BenchmarkTest_updateAccountPeers100(b *testing.B) {
	account := initTestAccount(b, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash100(b *testing.B) {
	account := initTestAccount(b, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff100(b *testing.B) {
	account := initTestAccount(b, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

// 1000 - 6717416375 ns/op
// 500 -  1732888875 ns/op
func BenchmarkTest_updateAccountPeers200(b *testing.B) {
	account := initTestAccount(b, 200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash200(b *testing.B) {
	account := initTestAccount(b, 200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff200(b *testing.B) {
	account := initTestAccount(b, 200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

func BenchmarkTest_updateAccountPeers500(b *testing.B) {
	account := initTestAccount(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash500(b *testing.B) {
	account := initTestAccount(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff500(b *testing.B) {
	account := initTestAccount(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

func BenchmarkTest_updateAccountPeers1000(b *testing.B) {
	account := initTestAccount(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash1000(b *testing.B) {
	account := initTestAccount(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff1000(b *testing.B) {
	account := initTestAccount(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

func BenchmarkTest_updateAccountPeers1500(b *testing.B) {
	account := initTestAccount(b, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash1500(b *testing.B) {
	account := initTestAccount(b, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff1500(b *testing.B) {
	account := initTestAccount(b, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

func BenchmarkTest_updateAccountPeers2000(b *testing.B) {
	account := initTestAccount(b, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateAccountPeers(account)
	}
}

// 1000 - 28943404000 ns/op
// 500 -   7365024500 ns/op
func BenchmarkTest_updateAccountPeersWithHash2000(b *testing.B) {
	account := initTestAccount(b, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithHash(account)
	}
}

func BenchmarkTest_updateAccountPeersWithDiff2000(b *testing.B) {
	account := initTestAccount(b, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Debug(i)
		updateAccountPeersWithDiff(account)
	}
}

type TestStruct struct {
	Name     string
	Value    int
	Ignored  string `diff:"-" hash:"ignore"`
	Compared string
}

func TestDiffIgnoreTag(t *testing.T) {
	a := TestStruct{
		Name:     "test",
		Value:    30,
		Ignored:  "This should be ignored",
		Compared: "This should be compared",
	}

	b := TestStruct{
		Name:     "test",
		Value:    31,
		Ignored:  "This is different but should be ignored",
		Compared: "This is different and should be compared",
	}

	changelog, err := diff.Diff(a, b)
	assert.NoError(t, err)

	// Check that only the expected fields are in the changelog
	assert.Len(t, changelog, 2)

	// Check that the 'Age' field change is detected
	ageChange := getChangeForField(changelog, "Value")
	assert.NotNil(t, ageChange)
	assert.Equal(t, 30, ageChange.From)
	assert.Equal(t, 31, ageChange.To)

	// Check that the 'Compared' field change is detected
	comparedChange := getChangeForField(changelog, "Compared")
	assert.NotNil(t, comparedChange)
	assert.Equal(t, "This should be compared", comparedChange.From)
	assert.Equal(t, "This is different and should be compared", comparedChange.To)

	// Check that the 'Ignored' field is not in the changelog
	ignoredChange := getChangeForField(changelog, "Ignored")
	assert.Nil(t, ignoredChange)
}

func TestHashIgnoreTag(t *testing.T) {
	a := TestStruct{
		Name:     "test",
		Value:    30,
		Ignored:  "This should be ignored",
		Compared: "This should be compared",
	}

	b := TestStruct{
		Name:     "test",
		Value:    30,
		Ignored:  "This is different but should be ignored",
		Compared: "This should be compared",
	}

	c := TestStruct{
		Name:     "test",
		Value:    31,
		Ignored:  "This should be ignored",
		Compared: "This should be compared",
	}

	d := TestStruct{
		Name:     "test",
		Value:    30,
		Ignored:  "This should be ignored",
		Compared: "This is different and should be compared",
	}

	opts := &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
		SlicesAsSets:    true,
		UseStringer:     true,
	}

	hashA, err := hashstructure.Hash(a, hashstructure.FormatV2, opts)
	assert.NoError(t, err)

	hashB, err := hashstructure.Hash(b, hashstructure.FormatV2, opts)
	assert.NoError(t, err)

	hashC, err := hashstructure.Hash(c, hashstructure.FormatV2, opts)
	assert.NoError(t, err)

	hashD, err := hashstructure.Hash(d, hashstructure.FormatV2, opts)
	assert.NoError(t, err)

	// Test that changing the ignored field does not change the hash
	assert.Equal(t, hashA, hashB)

	// Test that changing a non-ignored field does change the hash
	assert.NotEqual(t, hashA, hashC)
	assert.NotEqual(t, hashA, hashD)
}

func getChangeForField(changelog diff.Changelog, fieldName string) *diff.Change {
	for _, change := range changelog {
		if change.Path[0] == fieldName {
			return &change
		}
	}
	return nil
}
