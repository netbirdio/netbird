package metrics

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	prometheus2 "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

const defaultEndpoint = "/metrics"

// Metrics holds the metrics information and exposes it
type Metrics struct {
	Meter    api.Meter
	provider *metric.MeterProvider
	Endpoint string

	*http.Server
}

// NewServer initializes and returns a new Metrics instance
func NewServer(port int, endpoint string) (*Metrics, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	pkg := reflect.TypeOf(defaultEndpoint).PkgPath()
	meter := provider.Meter(pkg)

	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	router := http.NewServeMux()
	router.Handle(endpoint, promhttp.HandlerFor(
		prometheus2.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true}))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}

	return &Metrics{
		Meter:    meter,
		provider: provider,
		Endpoint: endpoint,
		Server:   server,
	}, nil
}

// Shutdown stops the metrics server
func (m *Metrics) Shutdown(ctx context.Context) error {
	if err := m.Server.Shutdown(ctx); err != nil {
		return fmt.Errorf("http server: %w", err)
	}

	if err := m.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("meter provider: %w", err)
	}

	return nil
}
