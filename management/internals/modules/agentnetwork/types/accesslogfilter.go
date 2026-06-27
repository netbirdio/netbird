package types

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// AccessLogDefaultPageSize is the default number of records per page.
	AccessLogDefaultPageSize = 50
	// AccessLogMaxPageSize is the maximum number of records allowed per page.
	AccessLogMaxPageSize = 100

	accessLogDefaultSortBy    = "timestamp"
	accessLogDefaultSortOrder = "desc"

	// usageOverviewDefaultLookback bounds an unbounded usage-overview query so
	// it never aggregates an account's entire history into memory.
	usageOverviewDefaultLookback = 90 * 24 * time.Hour
	// usageOverviewMaxRange caps how far back an explicit range may reach.
	usageOverviewMaxRange = 366 * 24 * time.Hour
)

// ApplyUsageOverviewBounds bounds a missing or over-wide date range so the
// in-memory usage aggregation can't load an account's full usage history. An
// absent range defaults to the last usageOverviewDefaultLookback; a range wider
// than usageOverviewMaxRange is clamped from the (possibly defaulted) end.
func (f *AgentNetworkAccessLogFilter) ApplyUsageOverviewBounds(now time.Time) {
	end := now
	if f.EndDate != nil {
		end = *f.EndDate
	}
	f.EndDate = &end
	if f.StartDate == nil {
		start := end.Add(-usageOverviewDefaultLookback)
		f.StartDate = &start
		return
	}
	if end.Sub(*f.StartDate) > usageOverviewMaxRange {
		start := end.Add(-usageOverviewMaxRange)
		f.StartDate = &start
	}
}

// accessLogSortFields maps the API sort_by values to their database columns.
var accessLogSortFields = map[string]string{
	"timestamp":    "timestamp",
	"model":        "model",
	"provider":     "provider",
	"status_code":  "status_code",
	"duration":     "duration",
	"cost_usd":     "cost_usd",
	"total_tokens": "total_tokens",
	"user_id":      "user_id",
	"decision":     "decision",
}

// AgentNetworkAccessLogFilter holds pagination, filtering and sorting
// parameters for the agent-network access-log listing. Group / provider /
// model are multi-valued (the UI uses multi-select; an entry matches when it
// matches any selected value).
type AgentNetworkAccessLogFilter struct {
	Page     int
	PageSize int

	SortBy    string
	SortOrder string

	Search      *string    // log id, host, path, model, user email/name
	UserID      *string    // exact user id (the dashboard sends the picked user's id)
	SessionID   *string    // exact session id — groups one conversation / coding session
	GroupIDs    []string   // authorising group ids (match any)
	ProviderIDs []string   // resolved provider ids (match any)
	Models      []string   // models (match any)
	Decision    *string    // policy decision (allow/deny)
	PathPrefix  *string    // request path prefix (path LIKE 'prefix%')
	StartDate   *time.Time // timestamp >= start_date
	EndDate     *time.Time // timestamp <= end_date
}

// ParseFromRequest fills the filter from the request query parameters. It
// returns a validation error when a supplied start_date / end_date is present
// but not valid RFC3339: silently dropping a malformed date would broaden the
// query (and, for the usage overview, fall back to the default window).
func (f *AgentNetworkAccessLogFilter) ParseFromRequest(r *http.Request) error {
	q := r.URL.Query()

	f.Page = parseAccessLogPositiveInt(q.Get("page"), 1)
	f.PageSize = min(parseAccessLogPositiveInt(q.Get("page_size"), AccessLogDefaultPageSize), AccessLogMaxPageSize)

	f.SortBy = parseAccessLogSortField(q.Get("sort_by"))
	f.SortOrder = parseAccessLogSortOrder(q.Get("sort_order"))

	f.Search = parseAccessLogOptionalString(q.Get("search"))
	f.UserID = parseAccessLogOptionalString(q.Get("user_id"))
	f.SessionID = parseAccessLogOptionalString(q.Get("session_id"))
	f.Decision = parseAccessLogOptionalString(q.Get("decision"))
	f.PathPrefix = parseAccessLogOptionalString(q.Get("path"))
	// Multi-value filters accept either repeated params (?group_id=a&group_id=b)
	// or a single comma-separated value (?group_id=a,b) so both the OpenAPI
	// array form and the dashboard's single-value query builder work.
	f.GroupIDs = splitMultiValue(q["group_id"])
	f.ProviderIDs = splitMultiValue(q["provider_id"])
	f.Models = splitMultiValue(q["model"])

	var err error
	if f.StartDate, err = parseAccessLogOptionalRFC3339(q.Get("start_date")); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid start_date: %v", err)
	}
	if f.EndDate, err = parseAccessLogOptionalRFC3339(q.Get("end_date")); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid end_date: %v", err)
	}
	return nil
}

// GetSortColumn returns the database column for the active sort field.
func (f *AgentNetworkAccessLogFilter) GetSortColumn() string {
	if col, ok := accessLogSortFields[f.SortBy]; ok {
		return col
	}
	return accessLogSortFields[accessLogDefaultSortBy]
}

// GetSortOrder returns the normalised sort order ("ASC"/"DESC").
func (f *AgentNetworkAccessLogFilter) GetSortOrder() string {
	if strings.EqualFold(f.SortOrder, "asc") {
		return "ASC"
	}
	return "DESC"
}

// GetLimit returns the page size, defaulting/clamping when unset.
func (f *AgentNetworkAccessLogFilter) GetLimit() int {
	if f.PageSize <= 0 {
		return AccessLogDefaultPageSize
	}
	return min(f.PageSize, AccessLogMaxPageSize)
}

// GetOffset returns the zero-based row offset for the active page. Page is
// user-controlled, so the multiplication is guarded against int overflow.
func (f *AgentNetworkAccessLogFilter) GetOffset() int {
	limit := f.GetLimit()
	if f.Page <= 1 || limit <= 0 {
		return 0
	}
	if f.Page-1 > math.MaxInt/limit {
		return math.MaxInt - (math.MaxInt % limit)
	}
	return (f.Page - 1) * limit
}

func parseAccessLogPositiveInt(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return def
}

func parseAccessLogSortField(s string) string {
	if _, ok := accessLogSortFields[s]; ok {
		return s
	}
	return accessLogDefaultSortBy
}

func parseAccessLogSortOrder(s string) string {
	if strings.EqualFold(s, "asc") {
		return "asc"
	}
	return accessLogDefaultSortOrder
}

func parseAccessLogOptionalString(s string) *string {
	if s = strings.TrimSpace(s); s != "" {
		return &s
	}
	return nil
}

func parseAccessLogOptionalRFC3339(s string) (*time.Time, error) {
	if s = strings.TrimSpace(s); s == "" {
		return nil, nil //nolint:nilnil // not provided: no value and no error
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// splitMultiValue flattens repeated query params and comma-separated values
// into a single trimmed, blank-free list. Returns nil when nothing remains so
// callers can skip the filter entirely.
func splitMultiValue(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		for _, v := range strings.Split(raw, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
