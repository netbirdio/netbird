package metrics_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

func newTestMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()

	exporter, err := promexporter.New()
	if err != nil {
		t.Fatalf("create prometheus exporter: %v", err)
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	pkg := reflect.TypeOf(metrics.Metrics{}).PkgPath()
	meter := provider.Meter(pkg)

	m, err := metrics.New(context.Background(), meter)
	if err != nil {
		t.Fatalf("create metrics: %v", err)
	}
	return m
}

func TestL4ServiceGauge(t *testing.T) {
	m := newTestMetrics(t)

	m.L4ServiceAdded(types.ServiceModeTCP)
	m.L4ServiceAdded(types.ServiceModeTCP)
	m.L4ServiceAdded(types.ServiceModeUDP)
	m.L4ServiceRemoved(types.ServiceModeTCP)
}

func TestTCPRelayMetrics(t *testing.T) {
	m := newTestMetrics(t)

	acct := types.AccountID("acct-1")

	m.TCPRelayStarted(acct)
	m.TCPRelayStarted(acct)
	m.TCPRelayEnded(acct, 10*time.Second, 1000, 500)
	m.TCPRelayDialError(acct)
	m.TCPRelayRejected(acct)
}

func TestUDPSessionMetrics(t *testing.T) {
	m := newTestMetrics(t)

	acct := types.AccountID("acct-2")

	m.UDPSessionStarted(acct)
	m.UDPSessionStarted(acct)
	m.UDPSessionEnded(acct)
	m.UDPSessionDialError(acct)
	m.UDPSessionRejected(acct)
	m.UDPPacketRelayed(types.RelayDirectionClientToBackend, 100)
	m.UDPPacketRelayed(types.RelayDirectionClientToBackend, 200)
	m.UDPPacketRelayed(types.RelayDirectionBackendToClient, 150)
}
