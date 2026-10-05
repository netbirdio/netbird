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
	files     atomic.Pointer[[]File]
	gathering atomic.Bool
}

// Refresh gathers the info with the posture checks evaluated, bounded by timeout. It
// reports false on a timeout, and also while the gathering of an earlier call that timed
// out is still blocked in a system call: starting another would only add one more
// goroutine stuck on the same call.
func (s *InfoSource) Refresh(ctx context.Context, timeout time.Duration, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, bool) {
	if !s.gathering.CompareAndSwap(false, true) {
		log.Warnf("system info gathering from an earlier sync is still running, skipping this one")
		return nil, false
	}
	release := sync.OnceFunc(func() { s.gathering.Store(false) })
	info, ok := getInfoWithChecksTimeout(ctx, timeout, checks, release, excludeIPs...)
	if !ok {
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
