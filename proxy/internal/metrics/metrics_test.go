package metrics_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
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

	m := metrics.New(prometheus.NewRegistry())

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
