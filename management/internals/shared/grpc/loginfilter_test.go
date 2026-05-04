package grpc

import (
	"hash/fnv"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func testAdvancedCfg() *lfConfig {
	return &lfConfig{
		reconnThreshold:   50 * time.Millisecond,
		baseBlockDuration: 100 * time.Millisecond,
		reconnLimitForBan: 3,
		metaChangeLimit:   2,
	}
}

type LoginFilterTestSuite struct {
	suite.Suite
	filter *loginFilter
}

func (s *LoginFilterTestSuite) SetupTest() {
	s.filter = newLoginFilterWithCfg(testAdvancedCfg())
}

func TestLoginFilterTestSuite(t *testing.T) {
	suite.Run(t, new(LoginFilterTestSuite))
}

func (s *LoginFilterTestSuite) TestFirstLoginIsAlwaysAllowed() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)

	s.True(s.filter.allowLogin(pubKey, meta))

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	s.Equal(1, s.filter.logged[pubKey].sessionCounter)
}

func (s *LoginFilterTestSuite) TestFlappingSameHashTriggersBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.False(s.filter.allowLogin(pubKey, meta))
	s.Require().Contains(s.filter.logged, pubKey)
	s.True(s.filter.logged[pubKey].isBanned)
}

func (s *LoginFilterTestSuite) TestBanDurationIncreasesExponentially() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan
	baseBan := s.filter.cfg.baseBlockDuration

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}
	s.Require().Contains(s.filter.logged, pubKey)
	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(1, s.filter.logged[pubKey].banLevel)
	firstBanDuration := s.filter.logged[pubKey].banExpiresAt.Sub(s.filter.logged[pubKey].lastSeen)
	s.InDelta(baseBan, firstBanDuration, float64(time.Millisecond))

	s.filter.logged[pubKey].banExpiresAt = time.Now().Add(-time.Second)
	s.filter.logged[pubKey].isBanned = false

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}
	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(2, s.filter.logged[pubKey].banLevel)
	secondBanDuration := s.filter.logged[pubKey].banExpiresAt.Sub(s.filter.logged[pubKey].lastSeen)
	// nolint
	expectedSecondDuration := time.Duration(float64(baseBan) * math.Pow(2, 1))
	s.InDelta(expectedSecondDuration, secondBanDuration, float64(time.Millisecond))
}

func (s *LoginFilterTestSuite) TestPeerIsAllowedAfterBanExpires() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)

	s.filter.logged[pubKey] = &peerState{
		isBanned:     true,
		banExpiresAt: time.Now().Add(-(s.filter.cfg.baseBlockDuration + time.Second)),
	}

	s.True(s.filter.allowLogin(pubKey, meta))

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	s.False(s.filter.logged[pubKey].isBanned)
}

func (s *LoginFilterTestSuite) TestBanLevelResetsAfterGoodBehavior() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)

	s.filter.logged[pubKey] = &peerState{
		currentHash: meta,
		banLevel:    3,
		lastSeen:    time.Now().Add(-3 * s.filter.cfg.baseBlockDuration),
	}

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	s.Equal(0, s.filter.logged[pubKey].banLevel)
}

func (s *LoginFilterTestSuite) TestFlappingDifferentHashesTriggersBlock() {
	pubKey := "PUB_KEY_A"
	limit := s.filter.cfg.metaChangeLimit

	for i := range limit {
		s.filter.addLogin(pubKey, uint64(i+1))
	}

	s.Require().Contains(s.filter.logged, pubKey)
	s.Equal(limit, s.filter.logged[pubKey].metaChangeCounter)

	isAllowed := s.filter.allowLogin(pubKey, uint64(limit+1))

	s.False(isAllowed, "should block new meta hash after limit is reached")
}

func (s *LoginFilterTestSuite) TestMetaChangeIsAllowedAfterWindowResets() {
	pubKey := "PUB_KEY_A"
	meta1 := uint64(1)
	meta2 := uint64(2)
	meta3 := uint64(3)

	s.filter.addLogin(pubKey, meta1)
	s.filter.addLogin(pubKey, meta2)
	s.Require().Contains(s.filter.logged, pubKey)
	s.Equal(s.filter.cfg.metaChangeLimit, s.filter.logged[pubKey].metaChangeCounter)
	s.False(s.filter.allowLogin(pubKey, meta3), "should be blocked inside window")

	s.filter.logged[pubKey].metaChangeWindowStart = time.Now().Add(-(s.filter.cfg.reconnThreshold + time.Second))

	s.True(s.filter.allowLogin(pubKey, meta3), "should be allowed after window expires")

	s.filter.addLogin(pubKey, meta3)
	s.Equal(1, s.filter.logged[pubKey].metaChangeCounter, "meta change counter should reset")
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

func BenchmarkLoginFilter_ParallelLoad(b *testing.B) {
	filter := newLoginFilterWithCfg(testAdvancedCfg())
	numKeys := 100000
	pubKeys := make([]string, numKeys)
	for i := range numKeys {
		pubKeys[i] = "PUB_KEY_" + strconv.Itoa(i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for pb.Next() {
			key := pubKeys[r.Intn(numKeys)]
			meta := r.Uint64()

			if filter.allowLogin(key, meta) {
				filter.addLogin(key, meta)
			}
		}
	})
}
