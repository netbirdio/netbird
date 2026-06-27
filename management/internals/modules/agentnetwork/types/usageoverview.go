package types

import (
	"sort"
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// UsageGranularity is the time-bucket width for the usage overview. New values
// can be added here and handled in bucketStart without touching the store.
type UsageGranularity string

const (
	UsageGranularityDay   UsageGranularity = "day"
	UsageGranularityWeek  UsageGranularity = "week"
	UsageGranularityMonth UsageGranularity = "month"
)

// ParseUsageGranularity maps the API query value to a granularity, defaulting
// to day for empty/unknown input.
func ParseUsageGranularity(s string) UsageGranularity {
	switch UsageGranularity(s) {
	case UsageGranularityWeek:
		return UsageGranularityWeek
	case UsageGranularityMonth:
		return UsageGranularityMonth
	default:
		return UsageGranularityDay
	}
}

// AgentNetworkUsageBucket is one aggregated usage time bucket. PeriodStart is
// the UTC start of the bucket as YYYY-MM-DD.
type AgentNetworkUsageBucket struct {
	PeriodStart  string
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
	CostUSD      float64
}

// ToAPIResponse renders the bucket as the API representation.
func (b *AgentNetworkUsageBucket) ToAPIResponse() api.AgentNetworkUsageBucket {
	return api.AgentNetworkUsageBucket{
		PeriodStart:  b.PeriodStart,
		InputTokens:  b.InputTokens,
		OutputTokens: b.OutputTokens,
		TotalTokens:  b.TotalTokens,
		CostUsd:      b.CostUSD,
	}
}

// bucketStart truncates t (in UTC) to the start of its bucket for the given
// granularity. Week buckets start on Monday (ISO week).
func bucketStart(t time.Time, g UsageGranularity) time.Time {
	t = t.UTC()
	switch g {
	case UsageGranularityWeek:
		// Monday-start week. time.Weekday: Sunday=0..Saturday=6.
		offset := (int(t.Weekday()) + 6) % 7
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return day.AddDate(0, 0, -offset)
	case UsageGranularityMonth:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	default: // day
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
}

// AggregateUsageByGranularity buckets the usage rows by the requested
// granularity and returns the buckets ordered oldest-first. Aggregation is done
// in Go (rather than per-engine SQL date_trunc) so granularities stay portable
// across SQLite/Postgres/MySQL and easy to extend.
func AggregateUsageByGranularity(rows []*AgentNetworkUsage, g UsageGranularity) []*AgentNetworkUsageBucket {
	byPeriod := make(map[string]*AgentNetworkUsageBucket)
	for _, r := range rows {
		key := bucketStart(r.Timestamp, g).Format("2006-01-02")
		b := byPeriod[key]
		if b == nil {
			b = &AgentNetworkUsageBucket{PeriodStart: key}
			byPeriod[key] = b
		}
		b.InputTokens += r.InputTokens
		b.OutputTokens += r.OutputTokens
		b.TotalTokens += r.TotalTokens
		b.CostUSD += r.CostUSD
	}

	out := make([]*AgentNetworkUsageBucket, 0, len(byPeriod))
	for _, b := range byPeriod {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeriodStart < out[j].PeriodStart })
	return out
}
