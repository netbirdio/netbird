package metrics

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	prometheus2 "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"net"
	"net/http"
	"reflect"
)

const defaultEndpoint = "/metrics"

// AppMetrics is metrics interface
type AppMetrics interface {
	GetMeter() metric2.Meter
	Close() error
	Expose(port int, endpoint string) error
}

// defaultAppMetrics are core application metrics based on OpenTelemetry https://opentelemetry.io/
type defaultAppMetrics struct {
	// Meter can be used by different application parts to create counters and measure things
	Meter    metric2.Meter
	listener net.Listener
	ctx      context.Context
}

// Close stop application metrics HTTP handler and closes listener.
func (appMetrics *defaultAppMetrics) Close() error {
	if appMetrics.listener == nil {
		return nil
	}
	return appMetrics.listener.Close()
}

// Expose metrics on a given port and endpoint. If endpoint is empty a defaultEndpoint one will be used.
// Exposes metrics in the Prometheus format https://prometheus.io/
func (appMetrics *defaultAppMetrics) Expose(port int, endpoint string) error {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	rootRouter := mux.NewRouter()
	rootRouter.Handle(endpoint, promhttp.HandlerFor(
		prometheus2.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true}))
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	appMetrics.listener = listener
	go func() {
		err := http.Serve(listener, rootRouter)
		if err != nil {
			return
		}
	}()

	log.Infof("enabled application metrics and exposing on http://%s", listener.Addr().String())

	return nil
}

// GetMeter returns metrics meter that can be used to add various counters
func (appMetrics *defaultAppMetrics) GetMeter() metric2.Meter {
	return appMetrics.Meter
}

// NewDefaultAppMetrics and expose them via defaultEndpoint on a given HTTP port
func NewDefaultAppMetrics(ctx context.Context) (AppMetrics, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	pkg := reflect.TypeOf(defaultEndpoint).PkgPath()
	meter := provider.Meter(pkg)

	return &defaultAppMetrics{Meter: meter, ctx: ctx}, nil
}
