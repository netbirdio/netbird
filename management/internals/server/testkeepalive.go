package server

// Test-only keepalive overrides read from env. Unset env keeps stock behavior.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/keepalive"
)

const (
	envGRPCServerKASec = "NB_TEST_GRPC_SERVER_KA_SEC"
	envServerTCPKASec  = "NB_TEST_SERVER_TCP_KA_SEC"
)

type testKeepalive struct {
	// grpcTime overrides kasp.Time and enables HTTP/2 server pings on the
	// shared port, where gRPC runs via ServeHTTP and ignores kasp. 0 = stock.
	grpcTime time.Duration
	// tcpSet reports that tcp is used as net.ListenConfig.KeepAlive on every
	// server listener. Negative tcp disables TCP keepalive.
	tcpSet bool
	tcp    time.Duration
}

var testKA = sync.OnceValue(func() testKeepalive {
	ka := parseTestKeepalive(os.Getenv)
	ka.logEffective()
	return ka
})

func parseTestKeepalive(getenv func(string) string) testKeepalive {
	var ka testKeepalive

	if v := getenv(envGRPCServerKASec); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			log.Warnf("testka: ignoring %s=%q, want seconds > 0", envGRPCServerKASec, v)
		} else {
			ka.grpcTime = time.Duration(n) * time.Second
		}
	}

	if v := getenv(envServerTCPKASec); v != "" {
		n, err := strconv.Atoi(v)
		switch {
		case err != nil || n == 0 || n < -1:
			log.Warnf("testka: ignoring %s=%q, want -1 or seconds > 0", envServerTCPKASec, v)
		case n == -1:
			ka.tcpSet, ka.tcp = true, -1
		default:
			ka.tcpSet, ka.tcp = true, time.Duration(n)*time.Second
		}
	}

	return ka
}

func (ka testKeepalive) logEffective() {
	if ka.grpcTime == 0 && !ka.tcpSet {
		return
	}
	p := ka.serverParams()
	h2Ping := "off"
	if ka.grpcTime > 0 {
		h2Ping = ka.grpcTime.String()
	}
	tcp := "stock"
	switch {
	case ka.tcpSet && ka.tcp < 0:
		tcp = "off"
	case ka.tcpSet:
		tcp = ka.tcp.String()
	}
	log.Infof("testka: grpc keepalive time=%s timeout=%s, http2 server ping=%s timeout=%s, server tcp keepalive=%s",
		p.Time, p.Timeout, h2Ping, p.Timeout, tcp)
}

func (ka testKeepalive) serverParams() keepalive.ServerParameters {
	p := kasp
	if ka.grpcTime > 0 {
		p.Time = ka.grpcTime
	}
	return p
}

func (ka testKeepalive) listen(addr string) (net.Listener, error) {
	if !ka.tcpSet {
		return net.Listen("tcp", addr)
	}
	lc := net.ListenConfig{KeepAlive: ka.tcp}
	return lc.Listen(context.Background(), "tcp", addr)
}

func (ka testKeepalive) listenTLS(addr string, conf *tls.Config) (net.Listener, error) {
	if !ka.tcpSet {
		return tls.Listen("tcp", addr, conf)
	}
	ln, err := ka.listen(addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, conf), nil
}

// autocertListener replaces m.Listener(), which forces a 3 min TCP keepalive
// on accept, when the TCP keepalive env is set.
func (ka testKeepalive) autocertListener(m *autocert.Manager) (net.Listener, error) {
	if !ka.tcpSet {
		return m.Listener(), nil
	}
	return ka.listenTLS(":443", m.TLSConfig())
}

func (ka testKeepalive) serveTLS(ln net.Listener, handler http.Handler) error {
	if ka.grpcTime == 0 {
		return http.Serve(ln, handler)
	}
	srv := &http.Server{
		Handler: handler,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: ka.grpcTime,
			PingTimeout:     kasp.Timeout,
		},
	}
	return srv.Serve(ln)
}

func (ka testKeepalive) h2cServer() *http2.Server {
	if ka.grpcTime == 0 {
		return &http2.Server{}
	}
	return &http2.Server{
		ReadIdleTimeout: ka.grpcTime,
		PingTimeout:     kasp.Timeout,
	}
}
