package mcpapi

import (
	"sync"
	"time"
)

// usageBuckets is the number of hourly buckets Usage keeps: one day.
const usageBuckets = 24

// Usage counts MCP tool calls and the users making them over the last day, in hourly
// buckets, for the self-hosted metrics. It keeps user IDs only to count them and never
// reports them.
type Usage struct {
	mu      sync.Mutex
	buckets [usageBuckets]usageBucket
}

type usageBucket struct {
	hour  int64
	calls int
	users map[string]struct{}
}

// NewUsage returns an empty usage counter.
func NewUsage() *Usage {
	return &Usage{}
}

// record counts one tool call by userID.
func (u *Usage) record(userID string, now time.Time) {
	if u == nil {
		return
	}
	hour := now.Unix() / int64(time.Hour/time.Second)
	u.mu.Lock()
	defer u.mu.Unlock()
	b := &u.buckets[hour%usageBuckets]
	if b.hour != hour || b.users == nil {
		*b = usageBucket{hour: hour, users: make(map[string]struct{})}
	}
	b.calls++
	b.users[userID] = struct{}{}
}

// LastDay returns the tool calls and the distinct users that made them in the hour of now
// and the 23 hours before it.
func (u *Usage) LastDay(now time.Time) (calls, users int) {
	if u == nil {
		return 0, 0
	}
	hour := now.Unix() / int64(time.Hour/time.Second)
	u.mu.Lock()
	defer u.mu.Unlock()
	seen := make(map[string]struct{})
	for _, b := range u.buckets {
		if b.users == nil || b.hour <= hour-usageBuckets || b.hour > hour {
			continue
		}
		calls += b.calls
		for id := range b.users {
			seen[id] = struct{}{}
		}
	}
	return calls, len(seen)
}
