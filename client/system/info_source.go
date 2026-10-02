package system

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// InfoSource gathers the system info sent to management, keeping the posture
// check results from the last Refresh for the cheap Current snapshots.
type InfoSource struct {
	files atomic.Pointer[[]File]
}

// Refresh gathers the info with the posture checks evaluated, bounded by timeout.
func (s *InfoSource) Refresh(ctx context.Context, timeout time.Duration, checks []*proto.Checks, excludeIPs ...netip.Addr) (*Info, bool) {
	info, ok := GetInfoWithChecksTimeout(ctx, timeout, checks, excludeIPs...)
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
