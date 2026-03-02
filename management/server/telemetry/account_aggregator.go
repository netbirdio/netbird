package telemetry

import (
	"context"
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
	// Manual reader allows us to read metrics without exporting
	manualReader := sdkmetric.NewManualReader()

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
			if histogramData, ok := metric.Data.(metricdata.Histogram[int64]); ok {
				for _, dataPoint := range histogramData.DataPoints {
					var accountID string
					for _, attr := range dataPoint.Attributes.ToSlice() {
						if attr.Key == "account_id" {
							accountID = attr.Value.AsString()
							break
						}
					}

					if accountID == "" {
						continue
					}

					if accHist, exists := a.accounts[accountID]; exists {
						if now.Sub(accHist.lastUpdate) > a.MaxAge {
							delete(a.accounts, accountID)
							continue
						}
					}

					p95 := calculateP95FromHistogram(dataPoint)
					if p95 > 0 {
						p95s = append(p95s, p95)
					}
				}
			}
		}
	}

	return p95s
}

// calculateP95FromHistogram computes P95 from OTel histogram data
func calculateP95FromHistogram(dp metricdata.HistogramDataPoint[int64]) int64 {
	if dp.Count == 0 {
		return 0
	}

	targetCount := uint64(float64(dp.Count) * 0.95)
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
