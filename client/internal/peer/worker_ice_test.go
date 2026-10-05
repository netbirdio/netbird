package peer

import (
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pairStat(local, remote string, rtt time.Duration) ice.CandidatePairStats {
	return ice.CandidatePairStats{
		LocalCandidateID:     local,
		RemoteCandidateID:    remote,
		CurrentRoundTripTime: rtt.Seconds(),
	}
}

func TestLatencySamplerObserve(t *testing.T) {
	t.Run("first sample is taken as is", func(t *testing.T) {
		var s latencySampler

		got := s.observe(pairStat("local", "remote", 40*time.Millisecond))
		assert.Equal(t, 40*time.Millisecond, got.Latency, "the first sample has nothing to average with")
	})

	t.Run("zero round trip time is not recorded", func(t *testing.T) {
		var s latencySampler

		require.Zero(t, s.observe(pairStat("local", "remote", 0)).Latency, "a pair without an RTT sample yields no latency")

		// the first real sample still seeds the average
		assert.Equal(t, 20*time.Millisecond, s.observe(pairStat("local", "remote", 20*time.Millisecond)).Latency)
	})

	t.Run("single spike is damped", func(t *testing.T) {
		var s latencySampler

		s.observe(pairStat("local", "remote", 20*time.Millisecond))
		spiked := s.observe(pairStat("local", "remote", 220*time.Millisecond)).Latency

		// a single sample only contributes its weight of the 200ms delta
		assert.Equal(t, 50*time.Millisecond, spiked, "a single spike must not be reported in full")

		// and it decays again once the path is back to normal
		for range 10 {
			s.observe(pairStat("local", "remote", 20*time.Millisecond))
		}
		assert.Less(t, s.observe(pairStat("local", "remote", 20*time.Millisecond)).Latency, 30*time.Millisecond,
			"the average should return towards the steady state")
	})

	t.Run("sustained change is followed", func(t *testing.T) {
		var s latencySampler

		s.observe(pairStat("local", "remote", 20*time.Millisecond))

		// the route selection switch margin, see routemanager/client
		const switchMargin = 20 * time.Millisecond

		// at a 4s sample interval, 3 samples are about 12 seconds
		var latency time.Duration
		for range 3 {
			latency = s.observe(pairStat("local", "remote", 80*time.Millisecond)).Latency
		}
		assert.Greater(t, latency-20*time.Millisecond, switchMargin,
			"a sustained 60ms degradation must clear the switch margin within seconds")

		// and 10 more samples, about 40 seconds in total, get most of the way there
		for range 10 {
			latency = s.observe(pairStat("local", "remote", 80*time.Millisecond)).Latency
		}
		assert.Greater(t, latency, 70*time.Millisecond, "a sustained degradation must be tracked within tens of seconds")
	})

	// Smoothing narrows the scatter of a jittery path but leaves a residue, and
	// that residue is what route selection has to compare its margins against.
	// The reported noise has to describe it, so it has to grow with the jitter
	// and cover the movement of the smoothed value.
	t.Run("reported noise reflects the jitter of the path", func(t *testing.T) {
		// 100ms +/- 40ms, the same shape the netem jitter test uses
		jittery := []int{
			104, 138, 61, 96, 141, 72, 118, 65, 133, 88,
			59, 127, 92, 136, 68, 111, 143, 74, 99, 121,
		}
		steady := []int{
			100, 101, 99, 100, 102, 99, 100, 101, 100, 99, 101, 100, 99, 100, 101, 100, 99, 101, 100, 100,
			101, 99, 100, 102, 99, 100, 101, 100, 99, 101, 100, 99, 100, 101, 100, 99, 101, 100, 100, 101,
		}

		spreadAndNoise := func(raw []int) (spread, noise time.Duration) {
			var s latencySampler
			var minSmoothed, maxSmoothed time.Duration

			for i, ms := range raw {
				got := s.observe(pairStat("local", "remote", time.Duration(ms)*time.Millisecond))
				noise = got.Noise

				// skip the warmup, the first sample is taken as is
				if i < 5 {
					continue
				}
				if minSmoothed == 0 || got.Latency < minSmoothed {
					minSmoothed = got.Latency
				}
				if got.Latency > maxSmoothed {
					maxSmoothed = got.Latency
				}
			}

			return maxSmoothed - minSmoothed, noise
		}

		jitterySpread, jitteryNoise := spreadAndNoise(jittery)
		steadySpread, steadyNoise := spreadAndNoise(steady)

		assert.Greater(t, jitteryNoise, steadyNoise, "a jittery path must report more noise than a steady one")
		assert.Less(t, steadyNoise, time.Millisecond, "a steady path must report almost no noise, so the fixed margins decide")

		// the noise is a deviation, so a few of them have to cover the movement
		// of the smoothed value, which is what the switch margin relies on
		assert.Greater(t, 4*jitteryNoise, jitterySpread,
			"reported noise %v must account for the smoothed spread %v", jitteryNoise, jitterySpread)
		assert.Greater(t, 4*steadyNoise+time.Millisecond, steadySpread,
			"reported noise %v must account for the smoothed spread %v", steadyNoise, steadySpread)
	})

	t.Run("new candidate pair discards the previous average", func(t *testing.T) {
		var s latencySampler

		s.observe(pairStat("local", "remote", 200*time.Millisecond))
		got := s.observe(pairStat("local2", "remote2", 20*time.Millisecond)).Latency

		assert.Equal(t, 20*time.Millisecond, got, "samples of the previous path must not be carried over")
	})

	// A single raw sample is when the estimate deserves the least trust: with
	// zero reported noise, a lucky outlier could clear the switch margins and
	// move a route on its own.
	t.Run("a fresh path reports conservative noise", func(t *testing.T) {
		var s latencySampler

		first := s.observe(pairStat("local", "remote", 100*time.Millisecond))
		assert.Greater(t, first.Noise, 10*time.Millisecond, "a single-sample estimate must not be reported as noise-free")

		// steady samples shrink the uncertainty again
		var got LatencySample
		for range 40 {
			got = s.observe(pairStat("local", "remote", 100*time.Millisecond))
		}
		assert.Less(t, got.Noise, 2*time.Millisecond, "steady samples should earn the estimate its trust back")
	})

	t.Run("a pair change keeps the larger deviation of a jittery link", func(t *testing.T) {
		var s latencySampler

		// build up a deviation well above the reseed floor of the new path
		for _, ms := range []int{100, 180, 60, 170, 50, 190, 70, 160} {
			s.observe(pairStat("local", "remote", time.Duration(ms)*time.Millisecond))
		}
		before := s.deviation
		require.Greater(t, before, 25*time.Millisecond, "the jittery path should have accumulated deviation")

		s.observe(pairStat("local2", "remote2", 50*time.Millisecond))
		assert.GreaterOrEqual(t, s.deviation, before, "a pair change must not shrink the known jitter of the link")
	})
}
