package telemetry

import (
	"context"
	"fmt"
	"reflect"

	metric2 "go.opentelemetry.io/otel/metric"

	sharedMetrics "github.com/netbirdio/netbird/shared/metrics"
)

// MockAppMetrics mocks the AppMetrics interface
type MockAppMetrics struct {
	GetMeterFunc                 func() metric2.Meter
	RegistryFunc                 func() *sharedMetrics.Metrics
	IDPMetricsFunc               func() *IDPMetrics
	HTTPMiddlewareFunc           func() *HTTPMiddleware
	GRPCMetricsFunc              func() *GRPCMetrics
	StoreMetricsFunc             func() *StoreMetrics
	UpdateChannelMetricsFunc     func() *UpdateChannelMetrics
	AddAccountManagerMetricsFunc func() *AccountManagerMetrics
	EphemeralPeersMetricsFunc    func() *EphemeralPeersMetrics
}

// GetMeter mocks the GetMeter function of the AppMetrics interface
func (mock *MockAppMetrics) GetMeter() metric2.Meter {
	if mock.GetMeterFunc != nil {
		return mock.GetMeterFunc()
	}
	return nil
}

// Registry mocks the Registry function of the AppMetrics interface
func (mock *MockAppMetrics) Registry() *sharedMetrics.Metrics {
	if mock.RegistryFunc != nil {
		return mock.RegistryFunc()
	}
	return nil
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

// EphemeralPeersMetrics mocks the MockAppMetrics function of the EphemeralPeersMetrics interface
func (mock *MockAppMetrics) EphemeralPeersMetrics() *EphemeralPeersMetrics {
	if mock.EphemeralPeersMetricsFunc != nil {
		return mock.EphemeralPeersMetricsFunc()
	}
	return nil
}

// AppMetrics is metrics interface
type AppMetrics interface {
	GetMeter() metric2.Meter
	Registry() *sharedMetrics.Metrics
	IDPMetrics() *IDPMetrics
	HTTPMiddleware() *HTTPMiddleware
	GRPCMetrics() *GRPCMetrics
	StoreMetrics() *StoreMetrics
	UpdateChannelMetrics() *UpdateChannelMetrics
	AccountManagerMetrics() *AccountManagerMetrics
	EphemeralPeersMetrics() *EphemeralPeersMetrics
}

// defaultAppMetrics are core application metrics based on OpenTelemetry https://opentelemetry.io/
type defaultAppMetrics struct {
	registry              *sharedMetrics.Metrics
	idpMetrics            *IDPMetrics
	httpMiddleware        *HTTPMiddleware
	grpcMetrics           *GRPCMetrics
	storeMetrics          *StoreMetrics
	updateChannelMetrics  *UpdateChannelMetrics
	accountManagerMetrics *AccountManagerMetrics
	ephemeralMetrics      *EphemeralPeersMetrics
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

// EphemeralPeersMetrics returns metrics for the ephemeral peer cleanup loop
func (appMetrics *defaultAppMetrics) EphemeralPeersMetrics() *EphemeralPeersMetrics {
	return appMetrics.ephemeralMetrics
}

// Registry returns the shared registry that modules register their own instruments with.
func (appMetrics *defaultAppMetrics) Registry() *sharedMetrics.Metrics {
	return appMetrics.registry
}

// GetMeter returns metrics meter that can be used to add various counters
func (appMetrics *defaultAppMetrics) GetMeter() metric2.Meter {
	return appMetrics.registry.Meter
}

// InstrumentationScope names the management instrumentation; the Prometheus
// exporter reports it as the otel_scope_name label.
func InstrumentationScope() string {
	return reflect.TypeOf(defaultAppMetrics{}).PkgPath()
}

// NewDefaultAppMetrics creates its own registry and registers the management metrics with it.
func NewDefaultAppMetrics(ctx context.Context) (AppMetrics, error) {
	registry, err := sharedMetrics.New(InstrumentationScope())
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics registry: %w", err)
	}
	return NewAppMetrics(ctx, registry)
}

// NewAppMetrics registers the management metrics with the given registry.
func NewAppMetrics(ctx context.Context, registry *sharedMetrics.Metrics) (AppMetrics, error) {
	idpMetrics, err := sharedMetrics.Register(ctx, registry, NewIDPMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IDP metrics: %w", err)
	}

	middleware, err := sharedMetrics.Register(ctx, registry, NewMetricsMiddleware)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP middleware metrics: %w", err)
	}

	grpcMetrics, err := sharedMetrics.Register(ctx, registry, NewGRPCMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gRPC metrics: %w", err)
	}

	storeMetrics, err := sharedMetrics.Register(ctx, registry, NewStoreMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store metrics: %w", err)
	}

	updateChannelMetrics, err := sharedMetrics.Register(ctx, registry, NewUpdateChannelMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize update channel metrics: %w", err)
	}

	accountManagerMetrics, err := sharedMetrics.Register(ctx, registry, NewAccountManagerMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize account manager metrics: %w", err)
	}

	ephemeralMetrics, err := sharedMetrics.Register(ctx, registry, NewEphemeralPeersMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ephemeral peers metrics: %w", err)
	}

	return &defaultAppMetrics{
		registry:              registry,
		idpMetrics:            idpMetrics,
		httpMiddleware:        middleware,
		grpcMetrics:           grpcMetrics,
		storeMetrics:          storeMetrics,
		updateChannelMetrics:  updateChannelMetrics,
		accountManagerMetrics: accountManagerMetrics,
		ephemeralMetrics:      ephemeralMetrics,
	}, nil
}
