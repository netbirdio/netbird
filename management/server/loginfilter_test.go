package server

import (
	"hash/fnv"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func testCfg() *config {
	return &config{
		filterTimeout:     20 * time.Millisecond,
		reconnTreshold:    50 * time.Millisecond,
		blockDuration:     100 * time.Millisecond,
		reconnLimitForBan: 3,
	}
}

type LoginFilterTestSuite struct {
	suite.Suite
	filter *loginFilter
}

func (s *LoginFilterTestSuite) SetupTest() {
	s.filter = newLoginFilterWithCfg(testCfg())
}

func TestLoginFilterTestSuite(t *testing.T) {
	suite.Run(t, new(LoginFilterTestSuite))
}

func (s *LoginFilterTestSuite) TestFirstLogin() {
	pubKey := "PUB_KEY_A"
	meta := uint64(4353457657645)

	s.True(s.filter.allowLogin(pubKey, meta), "should allow a new peer")

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	s.Equal(1, s.filter.logged[pubKey].counter)
}

func (s *LoginFilterTestSuite) TestFlappingPeerTriggersBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(4353457657645)
	limit := s.filter.cfg.reconnLimitForBan

	for range limit {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.allowLogin(pubKey, meta), "should still allow login at the limit boundary")

	s.filter.addLogin(pubKey, meta)

	s.False(s.filter.allowLogin(pubKey, meta), "should deny login after exceeding the limit")
	s.True(s.filter.logged[pubKey].banned, "peer should be marked as banned")
}

func (s *LoginFilterTestSuite) TestBannedPeerIsDenied() {
	pubKey := "PUB_KEY_A"
	meta := uint64(4353457657645)

	s.filter.logged[pubKey] = metahash{
		hash:     meta,
		banned:   true,
		lastSeen: time.Now(),
	}

	s.False(s.filter.allowLogin(pubKey, meta))
}

func (s *LoginFilterTestSuite) TestPeerIsAllowedAfterBanExpires() {
	pubKey := "PUB_KEY_A"
	meta := uint64(4353457657645)

	s.filter.logged[pubKey] = metahash{
		hash:     meta,
		banned:   true,
		lastSeen: time.Now().Add(-(s.filter.cfg.blockDuration + time.Second)),
	}

	s.True(s.filter.allowLogin(pubKey, meta), "should allow login after ban expires")

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	entry := s.filter.logged[pubKey]
	s.False(entry.banned, "ban should be lifted on new login")
	s.Equal(1, entry.counter, "counter should be reset")
}

func (s *LoginFilterTestSuite) TestDifferentHashIsBlockedWhenActive() {
	pubKey := "PUB_KEY_A"
	meta1 := uint64(23424223423)
	meta2 := uint64(99878798987987)

	s.filter.addLogin(pubKey, meta1)

	s.False(s.filter.allowLogin(pubKey, meta2))
}

func (s *LoginFilterTestSuite) TestDifferentHashIsAllowedAfterTimeout() {
	pubKey := "PUB_KEY_A"
	meta1 := uint64(23424223423)
	meta2 := uint64(99878798987987)

	s.filter.addLogin(pubKey, meta1)

	s.Require().Contains(s.filter.logged, pubKey)
	entry := s.filter.logged[pubKey]
	entry.lastSeen = time.Now().Add(-(s.filter.cfg.filterTimeout + time.Second))
	s.filter.logged[pubKey] = entry

	s.True(s.filter.allowLogin(pubKey, meta2))
}

func (s *LoginFilterTestSuite) TestRemovedPeerCanLogin() {
	pubKey := "PUB_KEY_A"
	meta := uint64(4353457657645)

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)

	s.filter.removeLogin(pubKey)
	s.NotContains(s.filter.logged, pubKey)

	s.True(s.filter.allowLogin(pubKey, meta))
}

func BenchmarkHashingMethods(b *testing.B) {
	meta := nbpeer.PeerSystemMeta{
		WtVersion:          "1.25.1",
		OSVersion:          "Ubuntu 22.04.3 LTS",
		KernelVersion:      "5.15.0-76-generic",
		Hostname:           "prod-server-database-01",
		SystemSerialNumber: "PC-1234567890",
		NetworkAddresses:   []nbpeer.NetworkAddress{{Mac: "00:1B:44:11:3A:B7"}, {Mac: "00:1B:44:11:3A:B8"}},
	}
	pubip := "8.8.8.8"

	var resultString string
	var resultUint uint64

	b.Run("BuilderString", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultString = builderString(meta, pubip)
		}
	})

	b.Run("FnvHashToString", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultString = fnvHashToString(meta, pubip)
		}
	})

	b.Run("FnvHashToUint64 - used", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultUint = metaHash(meta, pubip)
		}
	})

	_ = resultString
	_ = resultUint
}

func fnvHashToString(meta nbpeer.PeerSystemMeta, pubip string) string {
	h := fnv.New64a()

	if len(meta.NetworkAddresses) != 0 {
		for _, na := range meta.NetworkAddresses {
			h.Write([]byte(na.Mac))
		}
	}

	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	h.Write([]byte(meta.SystemSerialNumber))
	h.Write([]byte(pubip))

	return strconv.FormatUint(h.Sum64(), 16)
}

func builderString(meta nbpeer.PeerSystemMeta, pubip string) string {
	mac := getMacAddress(meta.NetworkAddresses)
	estimatedSize := len(meta.WtVersion) + len(meta.OSVersion) + len(meta.KernelVersion) + len(meta.Hostname) + len(meta.SystemSerialNumber) +
		len(pubip) + len(mac) + 6

	var b strings.Builder
	b.Grow(estimatedSize)

	b.WriteString(meta.WtVersion)
	b.WriteByte('|')
	b.WriteString(meta.OSVersion)
	b.WriteByte('|')
	b.WriteString(meta.KernelVersion)
	b.WriteByte('|')
	b.WriteString(meta.Hostname)
	b.WriteByte('|')
	b.WriteString(meta.SystemSerialNumber)
	b.WriteByte('|')
	b.WriteString(pubip)
	b.WriteByte('|')
	b.WriteString(mac)

	return b.String()
}

func getMacAddress(nas []nbpeer.NetworkAddress) string {
	if len(nas) == 0 {
		return ""
	}
	macs := make([]string, 0, len(nas))
	for _, na := range nas {
		macs = append(macs, na.Mac)
	}
	return strings.Join(macs, "/")
}
