package telemetry

import (
	"context"
	"math"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// AccountDurationAggregator uses OpenTelemetry histograms per account to calculate P95
// without publishing individual account labels
type AccountDurationAggregator struct {
	mu            sync.RWMutex
	accounts      map[string]*accountHistogram
	meterProvider *sdkmetric.MeterProvider
	manualReader  *sdkmetric.ManualReader

	FlushInterval time.Duration
	MaxAge        time.Duration
	ctx           context.Context
}

type accountHistogram struct {
	histogram  metric.Int64Histogram
	lastUpdate time.Time
}

// NewAccountDurationAggregator creates aggregator using OTel histograms
func NewAccountDurationAggregator(ctx context.Context, flushInterval, maxAge time.Duration) *AccountDurationAggregator {
	manualReader := sdkmetric.NewManualReader(
		sdkmetric.WithTemporalitySelector(func(kind sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricdata.DeltaTemporality
		}),
	)

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(manualReader),
	)

	return &AccountDurationAggregator{
		accounts:      make(map[string]*accountHistogram),
		meterProvider: meterProvider,
		manualReader:  manualReader,
		FlushInterval: flushInterval,
		MaxAge:        maxAge,
		ctx:           ctx,
	}
}

// Record adds a duration for an account using OTel histogram
func (a *AccountDurationAggregator) Record(accountID string, duration time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	accHist, exists := a.accounts[accountID]
	if !exists {
		meter := a.meterProvider.Meter("account-aggregator")
		histogram, err := meter.Int64Histogram(
			"sync_duration_per_account",
			metric.WithUnit("milliseconds"),
		)
		if err != nil {
			return
		}

		accHist = &accountHistogram{
			histogram: histogram,
		}
		a.accounts[accountID] = accHist
	}

	accHist.histogram.Record(a.ctx, duration.Milliseconds(),
		metric.WithAttributes(attribute.String("account_id", accountID)))
	accHist.lastUpdate = time.Now()
}

// FlushAndGetP95s extracts P95 from each account's histogram
func (a *AccountDurationAggregator) FlushAndGetP95s() []int64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	var rm metricdata.ResourceMetrics
	err := a.manualReader.Collect(a.ctx, &rm)
	if err != nil {
		return nil
	}

	now := time.Now()
	p95s := make([]int64, 0, len(a.accounts))

	for _, scopeMetrics := range rm.ScopeMetrics {
		for _, metric := range scopeMetrics.Metrics {
			histogramData, ok := metric.Data.(metricdata.Histogram[int64])
			if !ok {
				continue
			}

			for _, dataPoint := range histogramData.DataPoints {
				a.processDataPoint(dataPoint, now, &p95s)
			}
		}
	}

	return p95s
}

// processDataPoint extracts P95 from a single histogram data point
func (a *AccountDurationAggregator) processDataPoint(dataPoint metricdata.HistogramDataPoint[int64], now time.Time, p95s *[]int64) {
	accountID := extractAccountID(dataPoint)
	if accountID == "" {
		return
	}

	if a.isStaleAccount(accountID, now) {
		delete(a.accounts, accountID)
		return
	}

	if p95 := calculateP95FromHistogram(dataPoint); p95 > 0 {
		*p95s = append(*p95s, p95)
	}
}

// extractAccountID retrieves the account_id from histogram data point attributes
func extractAccountID(dp metricdata.HistogramDataPoint[int64]) string {
	for _, attr := range dp.Attributes.ToSlice() {
		if attr.Key == "account_id" {
			return attr.Value.AsString()
		}
	}
	return ""
}

// isStaleAccount checks if an account hasn't been updated recently
func (a *AccountDurationAggregator) isStaleAccount(accountID string, now time.Time) bool {
	accHist, exists := a.accounts[accountID]
	if !exists {
		return false
	}
	return now.Sub(accHist.lastUpdate) > a.MaxAge
}

// calculateP95FromHistogram computes P95 from OTel histogram data
func calculateP95FromHistogram(dp metricdata.HistogramDataPoint[int64]) int64 {
	if dp.Count == 0 {
		return 0
	}

	targetCount := uint64(math.Ceil(float64(dp.Count) * 0.95))
	if targetCount == 0 {
		targetCount = 1
	}
	var cumulativeCount uint64

	for i, bucketCount := range dp.BucketCounts {
		cumulativeCount += bucketCount
		if cumulativeCount >= targetCount {
			if i < len(dp.Bounds) {
				return int64(dp.Bounds[i])
			}
			if maxVal, defined := dp.Max.Value(); defined {
				return maxVal
			}
			return dp.Sum / int64(dp.Count)
		}
	}

	return dp.Sum / int64(dp.Count)
}

// Shutdown cleans up resources
func (a *AccountDurationAggregator) Shutdown() error {
	return a.meterProvider.Shutdown(a.ctx)
}
