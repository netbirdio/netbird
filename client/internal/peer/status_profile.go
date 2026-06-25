package peer

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type StatusProfile struct {
	counts sync.Map
}

func NewStatusProfile(ctx context.Context) *StatusProfile {
	s := &StatusProfile{}
	go s.Start(ctx)
	return s
}

func (s *StatusProfile) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logCounts()
		}
	}
}

func (s *StatusProfile) inc(method string) {
	if s == nil {
		return
	}
	if v, ok := s.counts.Load(method); ok {
		v.(*atomic.Int64).Add(1)
		return
	}
	cnt := &atomic.Int64{}
	actual, _ := s.counts.LoadOrStore(method, cnt)
	actual.(*atomic.Int64).Add(1)
}

func (s *StatusProfile) snapshot() map[string]int64 {
	out := make(map[string]int64)
	s.counts.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func (s *StatusProfile) logCounts() {
	counts := s.snapshot()
	if len(counts) == 0 {
		log.Infof("status profile: no Status method calls so far")
		return
	}

	type kv struct {
		method string
		count  int64
	}
	sorted := make([]kv, 0, len(counts))
	var total int64
	for m, c := range counts {
		if c == 0 {
			continue
		}
		sorted = append(sorted, kv{m, c})
		total += c
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].method < sorted[j].method
	})

	var b strings.Builder
	for i, e := range sorted {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(e.method)
		b.WriteByte('=')
		b.WriteString(strconv.FormatInt(e.count, 10))
	}
	log.Infof("status profile (cumulative total=%d): %s", total, b.String())
}
