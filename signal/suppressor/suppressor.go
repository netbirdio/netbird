package suppressor

import (
	"fmt"
	"time"
)

const (

	// DefaultRepetitionThreshold determines after how many repetitions it will be suppressed. It is a counter
	DefaultRepetitionThreshold = 90 // If the peer repeats the packets every 10 seconds, suppress them after 15 minutes
	minRepetitionThreshold     = 3

	// minTimeBetweenPackages below this period do not check the repetitions
	minTimeBetweenPackages = 7 * time.Second
	toleranceRange         = 1 * time.Second
)

type PeerID string

type packageStat struct {
	lastSeen        time.Time      // last packet timestamp
	lastDelta       *time.Duration // time between same size of packages
	lastSize        int
	repetitionTimes int
}

type Opts struct {
	RepetitionThreshold int
}

// Suppressor filters repeated packages from peers to prevent spam or abuse.
//
// It works by keeping track of the timing and size of packages received
// from each peer. For each peer, it stores the last package size, the
// timestamp when it was seen, the time difference (delta) between consecutive
// packages of the same size, and a repetition counter.
//
// The suppressor uses the following rules:
//
//  1. **Short intervals**: If a package arrives sooner than minTimeBetweenPackages
//     since the last package, it is accepted without repetition checks. This
//     allows bursts or backoff recovery to pass through.
//
//  2. **Clock skew / negative delta**: If the system clock goes backward
//     and produces a negative delta, the package is accepted and the state
//     is reset to prevent exploitation.
//
//  3. **Size changes**: If the new package size differs from the previous
//     one, the package is accepted and the repetition counter is reset.
//
//  4. **Tolerance-based repetition detection**: If a package arrives with a
//     delta close to the previous delta (within the toleranceRange), it is
//     considered a repeated pattern and the repetition counter is incremented.
//
//  5. **Suppression**: Once the repetition counter exceeds repetitionThreshold,
//     further packages with the same timing pattern are suppressed.
//
// This design ensures that repeated or spammy traffic patterns are filtered
// while allowing legitimate variations due to network jitter or bursty traffic.
type Suppressor struct {
	repetitionThreshold int
	peers               map[PeerID]*packageStat
}

func NewSuppressor(opts *Opts) (*Suppressor, error) {
	threshold := DefaultRepetitionThreshold
	if opts != nil {
		if opts.RepetitionThreshold < minRepetitionThreshold {
			return nil, fmt.Errorf("invalid repetition threshold")
		}

		threshold = opts.RepetitionThreshold
	}

	return &Suppressor{
		repetitionThreshold: threshold,
		peers:               make(map[PeerID]*packageStat),
	}, nil
}

// PackageReceived handles a newly received package from a peer.
//
// Parameters:
//   - destination: the PeerID of the peer that sent the package
//   - size: the size of the package
//   - arrivedTime: the timestamp when the package arrived
//
// Returns:
//   - true if the package is accepted (not suppressed)
//   - false if the package is considered a repeated package and suppressed
func (s *Suppressor) PackageReceived(destination PeerID, size int, arrivedTime time.Time) bool {
	p, ok := s.peers[destination]
	if !ok {
		s.peers[destination] = &packageStat{
			lastSeen: arrivedTime,
			lastSize: size,
		}
		return true
	}

	if p.lastSize != size {
		p.lastSeen = arrivedTime
		p.lastSize = size
		p.lastDelta = nil
		p.repetitionTimes = 0
		return true
	}

	// Calculate delta
	delta := arrivedTime.Sub(p.lastSeen)

	// Clock went backwards - don't reset state to prevent exploitation
	// Just update timestamp and continue with existing state
	if delta < 0 {
		p.lastSeen = arrivedTime
		p.lastDelta = nil
		p.repetitionTimes = 0
		return true
	}

	// if it is below the threshold we want to allow because the backoff ticker is active
	if delta < minTimeBetweenPackages {
		p.lastSeen = arrivedTime
		p.lastDelta = nil
		p.repetitionTimes = 0
		return true
	}

	// case when we have only one package in the history
	if p.lastDelta == nil {
		p.lastSeen = arrivedTime
		p.lastDelta = &delta
		return true
	}

	if abs(delta-*p.lastDelta) > toleranceRange {
		p.lastSeen = arrivedTime
		p.lastDelta = &delta
		p.repetitionTimes = 0
		return true

	}
	p.lastSeen = arrivedTime
	p.lastDelta = &delta
	p.repetitionTimes++

	return p.repetitionTimes < s.repetitionThreshold
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
