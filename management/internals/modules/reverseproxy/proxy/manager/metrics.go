package manager

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type metrics struct {
	proxyConnectionCount   metric.Int64UpDownCounter
	serviceUpdateSendCount metric.Int64Counter
	proxyHeartbeatCount    metric.Int64Counter
}

func newMetrics(meter metric.Meter) (*metrics, error) {
	proxyConnectionCount, err := meter.Int64UpDownCounter(
		"management_proxy_connection_count",
		metric.WithDescription("Number of active proxy connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, err
	}

	serviceUpdateSendCount, err := meter.Int64Counter(
		"management_proxy_service_update_send_count",
		metric.WithDescription("Total number of service updates sent to proxies"),
		metric.WithUnit("{update}"),
	)
	if err != nil {
		return nil, err
	}

	proxyHeartbeatCount, err := meter.Int64Counter(
		"management_proxy_heartbeat_count",
		metric.WithDescription("Total number of proxy heartbeats received"),
		metric.WithUnit("{heartbeat}"),
	)
	if err != nil {
		return nil, err
	}

	return &metrics{
		proxyConnectionCount:   proxyConnectionCount,
		serviceUpdateSendCount: serviceUpdateSendCount,
		proxyHeartbeatCount:    proxyHeartbeatCount,
	}, nil
}

func (m *metrics) IncrementProxyConnectionCount(clusterAddr string) {
	m.proxyConnectionCount.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("cluster", clusterAddr),
		))
}

func (m *metrics) DecrementProxyConnectionCount(clusterAddr string) {
	m.proxyConnectionCount.Add(context.Background(), -1,
		metric.WithAttributes(
			attribute.String("cluster", clusterAddr),
		))
}

func (m *metrics) IncrementServiceUpdateSendCount(clusterAddr string) {
	m.serviceUpdateSendCount.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("cluster", clusterAddr),
		))
}

func (m *metrics) IncrementProxyHeartbeatCount() {
	m.proxyHeartbeatCount.Add(context.Background(), 1)
}
