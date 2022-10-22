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

const endpoint = "/metrics"

// AppMetrics is core application metrics based on OpenTelemetry https://opentelemetry.io/
type AppMetrics struct {
	// Meter can be used by different application parts to create counters and measure things
	Meter    metric2.Meter
	listener net.Listener
	ctx      context.Context
}

// Close stop application metrics HTTP handler and closes listener.
func (appMetrics *AppMetrics) Close() error {
	return appMetrics.listener.Close()
}

// CreateAppMetrics and expose them via endpoint on a given HTTP port
// The metrics are exposed in openmetrics Prometheus format https://prometheus.io/
func CreateAppMetrics(ctx context.Context, port int) (*AppMetrics, error) {
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}
	pkg := reflect.TypeOf(endpoint).PkgPath()
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	meter := provider.Meter(pkg)
	rootRouter := mux.NewRouter()
	rootRouter.Handle("/metrics", promhttp.HandlerFor(
		prometheus2.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true}))

	appMetrics := &AppMetrics{Meter: meter, listener: listener, ctx: ctx}

	go func() {
		err := http.Serve(listener, rootRouter)
		if err != nil {
			return
		}
	}()
	log.Infof("metrics enabled for package %v and listening on %s", pkg, listener.Addr().String())

	go func() {
		<-appMetrics.ctx.Done()
		_ = appMetrics.Close() //nolint
	}()

	return appMetrics, nil
}
