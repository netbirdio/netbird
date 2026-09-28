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
		maxBanLevel:       3,
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

func (s *LoginFilterTestSuite) TestReconnectStormAfterQuietPeriodTriggersBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan

	s.filter.addLogin(pubKey, meta)
	s.Require().Contains(s.filter.logged, pubKey)
	s.filter.logged[pubKey].sessionStart = time.Now().Add(-(s.filter.cfg.reconnThreshold + time.Second))

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.False(s.filter.allowLogin(pubKey, meta))
	s.True(s.filter.logged[pubKey].isBanned)
}

func (s *LoginFilterTestSuite) TestReconnectStormAfterBanExpiresTriggersBanAgain() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}
	s.Require().Contains(s.filter.logged, pubKey)
	s.Require().True(s.filter.logged[pubKey].isBanned)

	expired := time.Now().Add(-(s.filter.cfg.baseBlockDuration + time.Second))
	s.filter.logged[pubKey].banExpiresAt = expired
	s.filter.logged[pubKey].sessionStart = expired

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(2, s.filter.logged[pubKey].banLevel)
}

func (s *LoginFilterTestSuite) TestSlowReconnectsAcrossWindowsDoNotBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan

	for i := 0; i < limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}
	s.Require().Contains(s.filter.logged, pubKey)
	s.filter.logged[pubKey].sessionStart = time.Now().Add(-(s.filter.cfg.reconnThreshold + time.Second))

	for i := 0; i < limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.allowLogin(pubKey, meta))
	s.False(s.filter.logged[pubKey].isBanned)
}

func (s *LoginFilterTestSuite) TestBanLevelEscalatesWhenStormResumesRightAfterBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan
	banTime := time.Now().Add(-3 * s.filter.cfg.baseBlockDuration)

	s.filter.logged[pubKey] = &peerState{
		currentHash:  meta,
		isBanned:     true,
		banLevel:     1,
		banExpiresAt: time.Now().Add(-time.Millisecond),
		sessionStart: banTime,
		lastSeen:     banTime,
	}

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(2, s.filter.logged[pubKey].banLevel)
}

func (s *LoginFilterTestSuite) TestBanLevelResetsAfterQuietPeriodFollowingBan() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	quiet := 2*s.filter.cfg.baseBlockDuration + time.Second

	s.filter.logged[pubKey] = &peerState{
		currentHash:  meta,
		banLevel:     2,
		banExpiresAt: time.Now().Add(-s.filter.cfg.baseBlockDuration),
		lastSeen:     time.Now().Add(-2 * quiet),
	}

	s.filter.addLogin(pubKey, meta)
	s.Equal(2, s.filter.logged[pubKey].banLevel, "ban ended more recently than the quiet period")

	s.filter.logged[pubKey].banExpiresAt = time.Now().Add(-quiet)
	s.filter.logged[pubKey].lastSeen = time.Now().Add(-2 * quiet)

	s.filter.addLogin(pubKey, meta)
	s.Equal(0, s.filter.logged[pubKey].banLevel)
}

func (s *LoginFilterTestSuite) TestBanDurationIsCappedAtMaxLevel() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan
	maxLevel := s.filter.cfg.maxBanLevel

	s.filter.logged[pubKey] = &peerState{
		currentHash:  meta,
		banLevel:     maxLevel,
		sessionStart: time.Now(),
		lastSeen:     time.Now(),
	}

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(maxLevel, s.filter.logged[pubKey].banLevel)
	expected := s.filter.cfg.baseBlockDuration << (maxLevel - 1)
	s.InDelta(expected, s.filter.logged[pubKey].banExpiresAt.Sub(s.filter.logged[pubKey].lastSeen), float64(time.Millisecond))
}

func (s *LoginFilterTestSuite) TestEstablishedPeerReconnectingOnceIsAllowed() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	longAgo := time.Now().Add(-time.Hour)

	s.filter.logged[pubKey] = &peerState{
		currentHash:           meta,
		sessionCounter:        1,
		sessionStart:          longAgo,
		lastSeen:              longAgo,
		metaChangeWindowStart: longAgo,
		metaChangeCounter:     1,
	}

	s.True(s.filter.allowLogin(pubKey, meta))
	s.filter.addLogin(pubKey, meta)

	s.True(s.filter.allowLogin(pubKey, meta))
	s.False(s.filter.logged[pubKey].isBanned)
	s.Equal(1, s.filter.logged[pubKey].sessionCounter)
}

func (s *LoginFilterTestSuite) TestLoginsDuringActiveBanDoNotExtendIt() {
	pubKey := "PUB_KEY_A"
	meta := uint64(1)
	limit := s.filter.cfg.reconnLimitForBan

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}
	s.Require().Contains(s.filter.logged, pubKey)
	s.Require().True(s.filter.logged[pubKey].isBanned)
	expiresAt := time.Now().Add(time.Hour)
	s.filter.logged[pubKey].banExpiresAt = expiresAt
	lastSeen := s.filter.logged[pubKey].lastSeen

	for i := 0; i <= limit; i++ {
		s.filter.addLogin(pubKey, meta)
	}

	s.True(s.filter.logged[pubKey].isBanned)
	s.Equal(1, s.filter.logged[pubKey].banLevel)
	s.Equal(expiresAt, s.filter.logged[pubKey].banExpiresAt)
	s.Equal(lastSeen, s.filter.logged[pubKey].lastSeen)
	s.Equal(0, s.filter.logged[pubKey].sessionCounter)
}

func BenchmarkHashingMethods(b *testing.B) {
	meta := nbpeer.PeerSystemMeta{
		WtVersion:          "1.25.1",
		OSVersion:          "Ubuntu 22.04.3 LTS",
		KernelVersion:      "5.15.0-76-generic",
		Hostname:           "prod-server-database-01",
		SystemSerialNumber: "PC-1234567890",
	}

	var resultString string
	var resultUint uint64

	b.Run("BuilderString", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultString = builderString(meta)
		}
	})

	b.Run("FnvHashToString", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultString = fnvHashToString(meta)
		}
	})

	b.Run("FnvHashToUint64 - used", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resultUint = metaHash(meta)
		}
	})

	_ = resultString
	_ = resultUint
}

func fnvHashToString(meta nbpeer.PeerSystemMeta) string {
	h := fnv.New64a()

	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	h.Write([]byte(meta.SystemSerialNumber))

	return strconv.FormatUint(h.Sum64(), 16)
}

func builderString(meta nbpeer.PeerSystemMeta) string {
	estimatedSize := len(meta.WtVersion) + len(meta.OSVersion) + len(meta.KernelVersion) + len(meta.Hostname) + len(meta.SystemSerialNumber) + 4

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

	return b.String()
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
