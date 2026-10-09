package roundtrip

import (
	"net/http"
	"testing"

	log "github.com/sirupsen/logrus"
)

// offersHTTP2 reports whether t will negotiate h2 with a TLS upstream.
// Clone forces t's one-time protocol setup, which registers an "h2"
// handler in t.TLSNextProto only when HTTP/2 ended up enabled.
func offersHTTP2(t *http.Transport) bool {
	_ = t.Clone()
	_, ok := t.TLSNextProto["h2"]
	return ok
}

func TestNewMultiTransportKeepsHTTP2AcrossClone(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{string(upstreamHTTPAuto), true},
		{string(upstreamHTTP2), true},
		{string(upstreamHTTP11), false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			t.Setenv(EnvUpstreamHTTPVersion, tc.version)
			m := NewMultiTransport(noEmbeddedRoundTripper{}, log.New())

			if got := offersHTTP2(m.direct.primary); got != tc.want {
				t.Errorf("direct transport offers h2 = %v, want %v", got, tc.want)
			}
			if got := offersHTTP2(m.insecure.primary); got != tc.want {
				t.Errorf("insecure transport offers h2 = %v, want %v", got, tc.want)
			}
		})
	}
}
