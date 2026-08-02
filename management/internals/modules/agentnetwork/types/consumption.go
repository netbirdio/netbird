package types

import "time"

// ConsumptionDimension classifies which kind of identity a consumption
// row counts against. The proxy-side enforcement layer ticks one row
// per dimension per request — typically one user row plus one group
// row.
type ConsumptionDimension string

const (
	// DimensionUser counts tokens / spend for a single end user. The
	// dim_id column carries the netbird user id (or peer.ID when the
	// caller is a tunnel-peer principal).
	DimensionUser ConsumptionDimension = "user"
	// DimensionGroup counts tokens / spend for a single source group
	// across every member of that group. The dim_id column carries
	// the netbird group id.
	DimensionGroup ConsumptionDimension = "group"
)

// Consumption is a per-dimension token + USD counter for a fixed
// aligned window. The (account, dim_kind, dim_id, window_seconds,
// window_start) tuple is the primary key; rows are rolled forward by
// the proxy's post-flight RecordLLMUsage path on every request.
//
// The same dim_id (e.g. a group id) gets one row per distinct
// window_seconds length in scope across the account's policies,
// because two policies with different window lengths read independent
// counters even though they share the dimension. Two policies with
// identical window_seconds on the same dimension share one counter
// (correct: their caps are checked against the same shared bucket).
type Consumption struct {
	AccountID      string               `gorm:"primaryKey;type:varchar(255)"`
	DimensionKind  ConsumptionDimension `gorm:"primaryKey;type:varchar(16);column:dim_kind"`
	DimensionID    string               `gorm:"primaryKey;type:varchar(255);column:dim_id"`
	WindowSeconds  int64                `gorm:"primaryKey;column:window_seconds"`
	WindowStartUTC time.Time            `gorm:"primaryKey;column:window_start_utc"`
	TokensInput    int64                `gorm:"column:tokens_input"`
	TokensOutput   int64                `gorm:"column:tokens_output"`
	CostUSD        float64              `gorm:"column:cost_usd"`
	UpdatedAt      time.Time
}

// TableName forces a stable name independent of GORM's pluraliser.
func (Consumption) TableName() string { return "agent_network_consumption" }

// ConsumptionKey identifies a single consumption counter within an account:
// the (dim_kind, dim_id, window_seconds, window_start) part of the row's
// primary key. Used to batch-read and batch-increment many counters for one
// request in a single store round-trip / transaction.
type ConsumptionKey struct {
	Kind           ConsumptionDimension
	DimID          string
	WindowSeconds  int64
	WindowStartUTC time.Time
}

// WindowStart returns the aligned UTC start of the window of length
// windowSeconds that contains t. Aligned to the unix epoch so the
// same bucket boundary is computed deterministically across processes.
func WindowStart(t time.Time, windowSeconds int64) time.Time {
	if windowSeconds <= 0 {
		return t.UTC()
	}
	step := windowSeconds * int64(time.Second)
	bucketed := t.UTC().UnixNano() / step * step
	return time.Unix(0, bucketed).UTC()
}
