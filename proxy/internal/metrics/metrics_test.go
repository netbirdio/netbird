package metrics_test

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/netbirdio/netbird/proxy/internal/metrics"
)

type testRoundTripper struct {
	response *http.Response
	err      error
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.response, t.err
}

func TestMetrics_RoundTripper(t *testing.T) {
	testResponse := http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
	}

	tests := map[string]struct {
		roundTripper http.RoundTripper
		request      *http.Request
		response     *http.Response
		err          error
	}{
		"ok": {
			roundTripper: &testRoundTripper{response: &testResponse},
			request:      &http.Request{Method: "GET", URL: &url.URL{Path: "/foo"}},
			response:     &testResponse,
		},
		"nil url": {
			roundTripper: &testRoundTripper{response: &testResponse},
			request:      &http.Request{Method: "GET", URL: nil},
			response:     &testResponse,
		},
		"nil response": {
			roundTripper: &testRoundTripper{response: nil},
			request:      &http.Request{Method: "GET", URL: &url.URL{Path: "/foo"}},
		},
	}

	exporter, err := prometheus.New()
	if err != nil {
		t.Fatalf("create prometheus exporter: %v", err)
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	pkg := reflect.TypeOf(metrics.Metrics{}).PkgPath()
	meter := provider.Meter(pkg)

	m, err := metrics.New(context.Background(), meter)
	if err != nil {
		t.Fatalf("create metrics: %v", err)
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rt := m.RoundTripper(test.roundTripper)
			res, err := rt.RoundTrip(test.request)
			if res != nil && res.Body != nil {
				defer res.Body.Close()
			}
			if diff := cmp.Diff(test.err, err); diff != "" {
				t.Errorf("Incorrect error (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.response, res); diff != "" {
				t.Errorf("Incorrect response (-want +got):\n%s", diff)
			}
		})
	}
}
