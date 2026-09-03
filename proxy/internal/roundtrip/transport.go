package roundtrip

import (
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Environment variable names for tuning the backend HTTP transport.
const (
	EnvMaxIdleConns          = "NB_PROXY_MAX_IDLE_CONNS"
	EnvMaxIdleConnsPerHost   = "NB_PROXY_MAX_IDLE_CONNS_PER_HOST"
	EnvMaxConnsPerHost       = "NB_PROXY_MAX_CONNS_PER_HOST"
	EnvIdleConnTimeout       = "NB_PROXY_IDLE_CONN_TIMEOUT"
	EnvTLSHandshakeTimeout   = "NB_PROXY_TLS_HANDSHAKE_TIMEOUT"
	EnvExpectContinueTimeout = "NB_PROXY_EXPECT_CONTINUE_TIMEOUT"
	EnvResponseHeaderTimeout = "NB_PROXY_RESPONSE_HEADER_TIMEOUT"
	EnvWriteBufferSize       = "NB_PROXY_WRITE_BUFFER_SIZE"
	EnvReadBufferSize        = "NB_PROXY_READ_BUFFER_SIZE"
	EnvDisableCompression    = "NB_PROXY_DISABLE_COMPRESSION"
	EnvMaxInflight           = "NB_PROXY_MAX_INFLIGHT"
	EnvUpstreamHTTPVersion   = "NB_PROXY_UPSTREAM_HTTP_VERSION"
)

// upstreamHTTPVersion selects the HTTP version the proxy uses towards an
// upstream. The explicit values are absolute: they mean the same thing
// however the transports are dialled and whatever the default becomes,
// so operator configuration survives a change of default.
type upstreamHTTPVersion string

const (
	// upstreamHTTPAuto leaves the choice to the proxy's own default.
	// This is the only value whose meaning tracks that default.
	upstreamHTTPAuto upstreamHTTPVersion = "auto"
	// upstreamHTTP11 never offers h2, so the upstream sees HTTP/1.1.
	upstreamHTTP11 upstreamHTTPVersion = "1.1"
	// upstreamHTTP2 offers h2 in the TLS handshake. Cleartext upstreams
	// stay on HTTP/1.1 regardless: the proxy speaks no h2c.
	upstreamHTTP2 upstreamHTTPVersion = "2"
)

// transportConfig holds tunable parameters for the per-account HTTP transport.
type transportConfig struct {
	maxIdleConns          int
	maxIdleConnsPerHost   int
	maxConnsPerHost       int
	idleConnTimeout       time.Duration
	tlsHandshakeTimeout   time.Duration
	expectContinueTimeout time.Duration
	responseHeaderTimeout time.Duration
	writeBufferSize       int
	readBufferSize        int
	disableCompression    bool
	// maxInflight limits per-backend concurrent requests. 0 means unlimited.
	maxInflight int
	// upstreamHTTPVersion selects the HTTP version used towards HTTPS
	// upstreams, for backends whose h2 support is advertised but
	// unusable.
	upstreamHTTPVersion upstreamHTTPVersion
}

func defaultTransportConfig() transportConfig {
	return transportConfig{
		maxIdleConns:          100,
		maxIdleConnsPerHost:   100,
		maxConnsPerHost:       0, // unlimited
		idleConnTimeout:       90 * time.Second,
		tlsHandshakeTimeout:   10 * time.Second,
		expectContinueTimeout: 1 * time.Second,
		upstreamHTTPVersion:   upstreamHTTPAuto,
	}
}

func loadTransportConfig(logger *log.Logger) transportConfig {
	cfg := defaultTransportConfig()

	if v, ok := envInt(EnvMaxIdleConns, logger); ok {
		cfg.maxIdleConns = v
	}
	if v, ok := envInt(EnvMaxIdleConnsPerHost, logger); ok {
		cfg.maxIdleConnsPerHost = v
	}
	if v, ok := envInt(EnvMaxConnsPerHost, logger); ok {
		cfg.maxConnsPerHost = v
	}
	if v, ok := envDuration(EnvIdleConnTimeout, logger); ok {
		cfg.idleConnTimeout = v
	}
	if v, ok := envDuration(EnvTLSHandshakeTimeout, logger); ok {
		cfg.tlsHandshakeTimeout = v
	}
	if v, ok := envDuration(EnvExpectContinueTimeout, logger); ok {
		cfg.expectContinueTimeout = v
	}
	if v, ok := envDuration(EnvResponseHeaderTimeout, logger); ok {
		cfg.responseHeaderTimeout = v
	}
	if v, ok := envInt(EnvWriteBufferSize, logger); ok {
		cfg.writeBufferSize = v
	}
	if v, ok := envInt(EnvReadBufferSize, logger); ok {
		cfg.readBufferSize = v
	}
	if v, ok := envBool(EnvDisableCompression, logger); ok {
		cfg.disableCompression = v
	}
	if v, ok := envInt(EnvMaxInflight, logger); ok {
		cfg.maxInflight = v
	}
	if v, ok := envUpstreamHTTPVersion(EnvUpstreamHTTPVersion, logger); ok {
		cfg.upstreamHTTPVersion = v
	}

	logger.WithFields(log.Fields{
		"max_idle_conns":          cfg.maxIdleConns,
		"max_idle_conns_per_host": cfg.maxIdleConnsPerHost,
		"max_conns_per_host":      cfg.maxConnsPerHost,
		"idle_conn_timeout":       cfg.idleConnTimeout,
		"tls_handshake_timeout":   cfg.tlsHandshakeTimeout,
		"expect_continue_timeout": cfg.expectContinueTimeout,
		"response_header_timeout": cfg.responseHeaderTimeout,
		"write_buffer_size":       cfg.writeBufferSize,
		"read_buffer_size":        cfg.readBufferSize,
		"disable_compression":     cfg.disableCompression,
		"max_inflight":            cfg.maxInflight,
		"upstream_http_version":   cfg.upstreamHTTPVersion,
	}).Debug("backend transport configuration")

	return cfg
}

// applyUpstreamHTTPVersion configures t for the requested HTTP version.
// It is the single place that decides what "auto" means, so changing the
// proxy's default only touches this function and leaves every explicit
// operator setting intact.
//
// HTTP/1.1 is pinned by clearing ForceAttemptHTTP2 and installing an
// empty TLSNextProto, which disables h2 regardless of how the transport
// is dialled. Relying on net/http's conservative default (h2 off
// whenever a custom dialer is set) would silently start negotiating h2
// again the day a transport switches to DialTLSContext.
func applyUpstreamHTTPVersion(t *http.Transport, version upstreamHTTPVersion) {
	if version == upstreamHTTP11 {
		t.ForceAttemptHTTP2 = false
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		return
	}
	t.ForceAttemptHTTP2 = true
}

// envUpstreamHTTPVersion reads an upstream HTTP version from the
// environment. An unrecognised value warns and leaves the default in
// place rather than guessing at the operator's intent.
func envUpstreamHTTPVersion(key string, logger *log.Logger) (upstreamHTTPVersion, bool) {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return "", false
	}
	switch v := upstreamHTTPVersion(strings.ToLower(s)); v {
	case upstreamHTTPAuto, upstreamHTTP11, upstreamHTTP2:
		return v, true
	default:
		logger.Warnf("ignoring unsupported %s=%q, expected one of %q, %q, %q",
			key, s, upstreamHTTPAuto, upstreamHTTP11, upstreamHTTP2)
		return "", false
	}
}

func envInt(key string, logger *log.Logger) (int, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		logger.Warnf("failed to parse %s=%q as int: %v", key, s, err)
		return 0, false
	}
	if v < 0 {
		logger.Warnf("ignoring negative value for %s=%d", key, v)
		return 0, false
	}
	return v, true
}

func envDuration(key string, logger *log.Logger) (time.Duration, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		logger.Warnf("failed to parse %s=%q as duration: %v", key, s, err)
		return 0, false
	}
	if v < 0 {
		logger.Warnf("ignoring negative value for %s=%s", key, v)
		return 0, false
	}
	return v, true
}

func envBool(key string, logger *log.Logger) (bool, bool) {
	s := os.Getenv(key)
	if s == "" {
		return false, false
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		logger.Warnf("failed to parse %s=%q as bool: %v", key, s, err)
		return false, false
	}
	return v, true
}
