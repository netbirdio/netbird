package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/gorilla/mux"
	prometheus2 "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

const defaultEndpoint = "/metrics"

// MockAppMetrics mocks the AppMetrics interface
type MockAppMetrics struct {
	GetMeterFunc                 func() metric2.Meter
	CloseFunc                    func() error
	ExposeFunc                   func(ctx context.Context, port int, endpoint string) error
	IDPMetricsFunc               func() *IDPMetrics
	HTTPMiddlewareFunc           func() *HTTPMiddleware
	GRPCMetricsFunc              func() *GRPCMetrics
	StoreMetricsFunc             func() *StoreMetrics
	UpdateChannelMetricsFunc     func() *UpdateChannelMetrics
	AddAccountManagerMetricsFunc func() *AccountManagerMetrics
}

// GetMeter mocks the GetMeter function of the AppMetrics interface
func (mock *MockAppMetrics) GetMeter() metric2.Meter {
	if mock.GetMeterFunc != nil {
		return mock.GetMeterFunc()
	}
	return nil
}

// Close mocks the Close function of the AppMetrics interface
func (mock *MockAppMetrics) Close() error {
	if mock.CloseFunc != nil {
		return mock.CloseFunc()
	}
	return fmt.Errorf("unimplemented")
}

// Expose mocks the Expose function of the AppMetrics interface
func (mock *MockAppMetrics) Expose(ctx context.Context, port int, endpoint string) error {
	if mock.ExposeFunc != nil {
		return mock.ExposeFunc(ctx, port, endpoint)
	}
	return fmt.Errorf("unimplemented")
}

// IDPMetrics mocks the IDPMetrics function of the IDPMetrics interface
func (mock *MockAppMetrics) IDPMetrics() *IDPMetrics {
	if mock.IDPMetricsFunc != nil {
		return mock.IDPMetricsFunc()
	}
	return nil
}

// HTTPMiddleware mocks the HTTPMiddleware function of the IDPMetrics interface
func (mock *MockAppMetrics) HTTPMiddleware() *HTTPMiddleware {
	if mock.HTTPMiddlewareFunc != nil {
		return mock.HTTPMiddlewareFunc()
	}
	return nil
}

// GRPCMetrics mocks the GRPCMetrics function of the IDPMetrics interface
func (mock *MockAppMetrics) GRPCMetrics() *GRPCMetrics {
	if mock.GRPCMetricsFunc != nil {
		return mock.GRPCMetricsFunc()
	}
	return nil
}

// StoreMetrics mocks the MockAppMetrics function of the StoreMetrics interface
func (mock *MockAppMetrics) StoreMetrics() *StoreMetrics {
	if mock.StoreMetricsFunc != nil {
		return mock.StoreMetricsFunc()
	}
	return nil
}

// UpdateChannelMetrics mocks the MockAppMetrics function of the UpdateChannelMetrics interface
func (mock *MockAppMetrics) UpdateChannelMetrics() *UpdateChannelMetrics {
	if mock.UpdateChannelMetricsFunc != nil {
		return mock.UpdateChannelMetricsFunc()
	}
	return nil
}

// AccountManagerMetrics mocks the MockAppMetrics function of the AccountManagerMetrics interface
func (mock *MockAppMetrics) AccountManagerMetrics() *AccountManagerMetrics {
	if mock.AddAccountManagerMetricsFunc != nil {
		return mock.AddAccountManagerMetricsFunc()
	}
	return nil
}

// AppMetrics is metrics interface
type AppMetrics interface {
	GetMeter() metric2.Meter
	Close() error
	Expose(ctx context.Context, port int, endpoint string) error
	IDPMetrics() *IDPMetrics
	HTTPMiddleware() *HTTPMiddleware
	GRPCMetrics() *GRPCMetrics
	StoreMetrics() *StoreMetrics
	UpdateChannelMetrics() *UpdateChannelMetrics
	AccountManagerMetrics() *AccountManagerMetrics
}

// defaultAppMetrics are core application metrics based on OpenTelemetry https://opentelemetry.io/
type defaultAppMetrics struct {
	// Meter can be used by different application parts to create counters and measure things
	Meter                 metric2.Meter
	listener              net.Listener
	ctx                   context.Context
	externallyManaged     bool
	idpMetrics            *IDPMetrics
	httpMiddleware        *HTTPMiddleware
	grpcMetrics           *GRPCMetrics
	storeMetrics          *StoreMetrics
	updateChannelMetrics  *UpdateChannelMetrics
	accountManagerMetrics *AccountManagerMetrics
}

// IDPMetrics returns metrics for the idp package
func (appMetrics *defaultAppMetrics) IDPMetrics() *IDPMetrics {
	return appMetrics.idpMetrics
}

// HTTPMiddleware returns metrics for the http api package
func (appMetrics *defaultAppMetrics) HTTPMiddleware() *HTTPMiddleware {
	return appMetrics.httpMiddleware
}

// GRPCMetrics returns metrics for the gRPC api
func (appMetrics *defaultAppMetrics) GRPCMetrics() *GRPCMetrics {
	return appMetrics.grpcMetrics
}

// StoreMetrics returns metrics for the store
func (appMetrics *defaultAppMetrics) StoreMetrics() *StoreMetrics {
	return appMetrics.storeMetrics
}

// UpdateChannelMetrics returns metrics for the updatechannel
func (appMetrics *defaultAppMetrics) UpdateChannelMetrics() *UpdateChannelMetrics {
	return appMetrics.updateChannelMetrics
}

// AccountManagerMetrics returns metrics for the account manager
func (appMetrics *defaultAppMetrics) AccountManagerMetrics() *AccountManagerMetrics {
	return appMetrics.accountManagerMetrics
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
func (appMetrics *defaultAppMetrics) Expose(ctx context.Context, port int, endpoint string) error {
	if appMetrics.externallyManaged {
		return nil
	}
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
		if err := http.Serve(listener, rootRouter); err != nil && err != http.ErrServerClosed {
			log.WithContext(ctx).Errorf("metrics server error: %v", err)
		}
		log.WithContext(ctx).Info("metrics server stopped")
	}()

	log.WithContext(ctx).Infof("enabled application metrics and exposing on http://%s", listener.Addr().String())

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
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	pkg := reflect.TypeOf(defaultEndpoint).PkgPath()
	meter := provider.Meter(pkg)

	idpMetrics, err := NewIDPMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IDP metrics: %w", err)
	}

	middleware, err := NewMetricsMiddleware(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP middleware metrics: %w", err)
	}

	grpcMetrics, err := NewGRPCMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gRPC metrics: %w", err)
	}

	storeMetrics, err := NewStoreMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store metrics: %w", err)
	}

	updateChannelMetrics, err := NewUpdateChannelMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize update channel metrics: %w", err)
	}

	accountManagerMetrics, err := NewAccountManagerMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize account manager metrics: %w", err)
	}

	return &defaultAppMetrics{
		Meter:                 meter,
		ctx:                   ctx,
		idpMetrics:            idpMetrics,
		httpMiddleware:        middleware,
		grpcMetrics:           grpcMetrics,
		storeMetrics:          storeMetrics,
		updateChannelMetrics:  updateChannelMetrics,
		accountManagerMetrics: accountManagerMetrics,
	}, nil
}

// NewAppMetricsWithMeter creates AppMetrics using an externally provided meter.
// The caller is responsible for exposing metrics via HTTP. Expose() and Close() are no-ops.
func NewAppMetricsWithMeter(ctx context.Context, meter metric2.Meter) (AppMetrics, error) {
	idpMetrics, err := NewIDPMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IDP metrics: %w", err)
	}

	middleware, err := NewMetricsMiddleware(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP middleware metrics: %w", err)
	}

	grpcMetrics, err := NewGRPCMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gRPC metrics: %w", err)
	}

	storeMetrics, err := NewStoreMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store metrics: %w", err)
	}

	updateChannelMetrics, err := NewUpdateChannelMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize update channel metrics: %w", err)
	}

	accountManagerMetrics, err := NewAccountManagerMetrics(ctx, meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize account manager metrics: %w", err)
	}

	return &defaultAppMetrics{
		Meter:                 meter,
		ctx:                   ctx,
		externallyManaged:     true,
		idpMetrics:            idpMetrics,
		httpMiddleware:        middleware,
		grpcMetrics:           grpcMetrics,
		storeMetrics:          storeMetrics,
		updateChannelMetrics:  updateChannelMetrics,
		accountManagerMetrics: accountManagerMetrics,
	}, nil
}
