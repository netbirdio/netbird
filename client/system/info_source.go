package system

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// infoLostAfter is how many timeouts an abandoned gathering is waited for before
	// another may start beside it. A system call that is merely slow returns well within
	// that; only one blocked for good, such as a stat on a dead network mount, is worked
	// around.
	infoLostAfter = 10

	// maxAbandoned bounds how many gatherings may be left blocked, so a call that never
	// returns cannot leak a goroutine on every refresh for the life of the daemon.
	maxAbandoned = 2
)

// InfoSource gathers the system info sent to management, keeping the posture
// check results from the last Refresh for the cheap Current snapshots. The zero value is
// ready to use.
type InfoSource struct {
	// started numbers Refresh calls in the order they began.
	started atomic.Uint64
	// now overrides the clock when set.
	now func() time.Time

	mu sync.Mutex
	// abandoned holds the start of each gathering that timed out and is still blocked in
	// a system call, by Refresh number.
	abandoned map[uint64]time.Time
	// files holds the file check results of the latest-started Refresh that succeeded,
	// filesFrom its number.
	files     []File
	filesFrom uint64
}

// Refresh gathers the info with the posture checks evaluated, bounded by timeout. It may
// run concurrently with other calls; the results Current reuses are those of the call
// that started last, so an older call finishing late cannot replace them. It reports
// false on a timeout, and also while a gathering that timed out earlier is still blocked
// in a system call: starting another would only add one more goroutine stuck on it.
// That one is given up on once it has run for infoLostAfter timeouts, up to maxAbandoned.
func (s *InfoSource) Refresh(ctx context.Context, timeout time.Duration, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, bool) {
	started := s.clock()
	if !s.mayStart(started, time.Duration(infoLostAfter)*timeout) {
		return nil, false
	}
	seq := s.started.Add(1)

	var mu sync.Mutex
	var finished, abandoned bool
	done := func() {
		mu.Lock()
		defer mu.Unlock()
		if finished {
			return
		}
		finished = true
		if abandoned {
			s.release(seq)
		}
	}
	info, ok := getInfoWithChecksTimeout(ctx, timeout, checks, done, excludeIPs...)
	if !ok {
		mu.Lock()
		if !finished {
			abandoned = true
			s.abandon(seq, started)
		}
		mu.Unlock()
		return nil, false
	}
	s.publishFiles(seq, info.Files)
	return info, true
}

// mayStart reports whether a gathering may start at now. Every abandoned gathering must
// have run for lost, and fewer than maxAbandoned may be left running.
func (s *InfoSource) mayStart(now time.Time, lost time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.abandoned) == 0 {
		return true
	}
	if len(s.abandoned) >= maxAbandoned {
		log.Warnf("%d system info gatherings are stuck, skipping this one", len(s.abandoned))
		return false
	}
	for _, started := range s.abandoned {
		if now.Sub(started) < lost {
			log.Warnf("system info gathering that timed out earlier is still running, skipping this one")
			return false
		}
	}
	log.Warnf("system info gathering has been stuck for over %s, starting another", lost)
	return true
}

// abandon records that gathering seq, started at started, timed out but is still running.
func (s *InfoSource) abandon(seq uint64, started time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.abandoned == nil {
		s.abandoned = map[uint64]time.Time{}
	}
	s.abandoned[seq] = started
}

// release records that the abandoned gathering seq has returned.
func (s *InfoSource) release(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.abandoned, seq)
}

func (s *InfoSource) abandonedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.abandoned)
}

func (s *InfoSource) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *InfoSource) publishFiles(seq uint64, files []File) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq < s.filesFrom {
		return
	}
	s.files = slices.Clone(files)
	s.filesFrom = seq
}

// Current gathers the info without evaluating the checks, reusing the last Refresh results.
func (s *InfoSource) Current(ctx context.Context, excludeIPs ...netip.Addr) *Info {
	info := GetInfo(ctx)
	info.removeAddresses(excludeIPs...)
	s.mu.Lock()
	info.Files = slices.Clone(s.files)
	s.mu.Unlock()
	return info
}
