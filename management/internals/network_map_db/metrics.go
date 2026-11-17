package networkmapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	readSourceReplica = "replica"
	readSourcePrimary = "primary"

	readReasonNoReplica       = "no_replica"
	readReasonCaughtUp        = "caught_up"
	readReasonLagTimeout      = "lag_timeout"
	readReasonReplicaError    = "replica_error"
	readReasonSerialReadError = "serial_read_error"
)

// Metrics records which database serves network map data reads, how long reads
// wait for the replica and the state of the connection pools.
type Metrics struct {
	reads       metric.Int64Counter
	replicaWait metric.Int64Histogram
}

// NewMetrics creates the network map data metrics on meter and observes the
// connection pools keyed by pool name.
func NewMetrics(meter metric.Meter, pools map[string]*pgxpool.Pool) (*Metrics, error) {
	reads, err := meter.Int64Counter("management.nmdata.reads",
		metric.WithUnit("1"),
		metric.WithDescription("Network map data reads by the database that served them and the reason it was chosen"),
	)
	if err != nil {
		return nil, fmt.Errorf("create reads counter: %w", err)
	}

	replicaWait, err := meter.Int64Histogram("management.nmdata.replica.wait.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Time a network map data read waited for the replica to replicate the primary's network serial"),
	)
	if err != nil {
		return nil, fmt.Errorf("create replica wait histogram: %w", err)
	}

	connections, err := meter.Int64ObservableGauge("management.nmdata.pool.connections",
		metric.WithUnit("1"),
		metric.WithDescription("Connections of the network map data connection pools by state"),
	)
	if err != nil {
		return nil, fmt.Errorf("create pool connections gauge: %w", err)
	}

	_, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		for name, pool := range pools {
			stat := pool.Stat()
			observePool(observer, connections, name, "acquired", stat.AcquiredConns())
			observePool(observer, connections, name, "idle", stat.IdleConns())
			observePool(observer, connections, name, "total", stat.TotalConns())
		}
		return nil
	}, connections)
	if err != nil {
		return nil, fmt.Errorf("create pool connections callback: %w", err)
	}

	return &Metrics{reads: reads, replicaWait: replicaWait}, nil
}

func observePool(observer metric.Observer, gauge metric.Int64ObservableGauge, pool, state string, value int32) {
	observer.ObserveInt64(gauge, int64(value), metric.WithAttributes(
		attribute.String("pool", pool),
		attribute.String("state", state),
	))
}

func (m *Metrics) countRead(ctx context.Context, source, reason string) {
	if m == nil {
		return
	}
	m.reads.Add(ctx, 1, metric.WithAttributes(
		attribute.String("source", source),
		attribute.String("reason", reason),
	))
}

func (m *Metrics) recordReplicaWait(ctx context.Context, wait time.Duration) {
	if m == nil {
		return
	}
	m.replicaWait.Record(ctx, wait.Milliseconds())
}
