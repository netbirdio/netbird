package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"

	prometheus2 "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
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

// New creates the meter that every module registers its instruments with,
// exported in Prometheus format. Scope names the instrumentation and shows up
// as the otel_scope_name label. Serve exposes the endpoint.
func New(scope string) (*Metrics, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	return &Metrics{Meter: provider.Meter(scope), provider: provider}, nil
}

// NewServer initializes and returns a new Metrics instance
func NewServer(port int, endpoint string) (*Metrics, error) {
	m, err := New(reflect.TypeOf(defaultEndpoint).PkgPath())
	if err != nil {
		return nil, err
	}
	otel.SetMeterProvider(m.provider)
	m.Endpoint, m.Server = newHTTPServer(port, endpoint)
	return m, nil
}

// Register builds a module's instruments against the shared meter.
func Register[T any](ctx context.Context, m *Metrics, build func(context.Context, api.Meter) (T, error)) (T, error) {
	return build(ctx, m.Meter)
}

// Serve exposes the endpoint on the given port in the background until
// Shutdown is called. Server.Addr holds the bound address afterwards. A
// registry that already has a server, such as one from NewServer, is exposed
// by its creator and left untouched.
func (m *Metrics) Serve(ctx context.Context, port int, endpoint string) error {
	if m.Server != nil {
		return nil
	}

	m.Endpoint, m.Server = newHTTPServer(port, endpoint)
	listener, err := net.Listen("tcp4", m.Server.Addr)
	if err != nil {
		return err
	}
	m.Server.Addr = listener.Addr().String()

	go func() {
		if err := m.Server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithContext(ctx).Errorf("metrics server error: %v", err)
		}
		log.WithContext(ctx).Info("metrics server stopped")
	}()

	log.WithContext(ctx).Infof("enabled application metrics and exposing on http://%s", m.Server.Addr)
	return nil
}

// Shutdown stops the metrics server
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.Server != nil {
		if err := m.Server.Shutdown(ctx); err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	if err := m.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("meter provider: %w", err)
	}

	return nil
}

func newHTTPServer(port int, endpoint string) (string, *http.Server) {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	router := http.NewServeMux()
	router.Handle(endpoint, promhttp.HandlerFor(
		prometheus2.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true}))

	return endpoint, &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}
}
