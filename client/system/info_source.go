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

// InfoSource gathers the system info sent to management, keeping the posture
// check results from the last Refresh for the cheap Current snapshots.
type InfoSource struct {
	files atomic.Pointer[[]File]
	// stuck counts gatherings that timed out and are still blocked in a system call.
	stuck atomic.Int32
}

// Refresh gathers the info with the posture checks evaluated, bounded by timeout. It may
// run concurrently with other calls. It reports false on a timeout, and also while a
// gathering that timed out earlier is still blocked in a system call: starting another
// would only add one more goroutine stuck on the same call.
func (s *InfoSource) Refresh(ctx context.Context, timeout time.Duration, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, bool) {
	if s.stuck.Load() > 0 {
		log.Warnf("system info gathering that timed out earlier is still running, skipping this one")
		return nil, false
	}

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
			s.stuck.Add(-1)
		}
	}
	info, ok := getInfoWithChecksTimeout(ctx, timeout, checks, done, excludeIPs...)
	if !ok {
		mu.Lock()
		if !finished {
			abandoned = true
			s.stuck.Add(1)
		}
		mu.Unlock()
		return nil, false
	}
	files := slices.Clone(info.Files)
	s.files.Store(&files)
	return info, true
}

// Current gathers the info without evaluating the checks, reusing the last Refresh results.
func (s *InfoSource) Current(ctx context.Context, excludeIPs ...netip.Addr) *Info {
	info := GetInfo(ctx)
	info.removeAddresses(excludeIPs...)
	if files := s.files.Load(); files != nil {
		info.Files = *files
	}
	return info
}
