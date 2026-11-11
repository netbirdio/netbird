package ws

// Test-only TCP keepalive override read from env. Unset env keeps stock behavior.

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envServerTCPKASec = "NB_TEST_SERVER_TCP_KA_SEC"

	testKAInterval = 15 * time.Second
	testKACount    = 3
)

// testKeepaliveConfig returns the keepalive config for accepted connections.
// ok is false when the env is unset or invalid, then the Go default applies.
func testKeepaliveConfig(getenv func(string) string) (cfg net.KeepAliveConfig, ok bool) {
	v := getenv(envServerTCPKASec)
	if v == "" {
		return cfg, false
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil || n == 0 || n < -1:
		log.Warnf("testka: ignoring %s=%q, want -1 or seconds > 0", envServerTCPKASec, v)
		return cfg, false
	case n == -1:
		return net.KeepAliveConfig{Enable: false}, true
	default:
		return net.KeepAliveConfig{
			Enable:   true,
			Idle:     time.Duration(n) * time.Second,
			Interval: testKAInterval,
			Count:    testKACount,
		}, true
	}
}

// listenTCP binds addr. With the env set, accepted connections get the test
// keepalive config in place of the Go default (15 s idle).
func listenTCP(addr string) (net.Listener, error) {
	cfg, ok := testKeepaliveConfig(os.Getenv)
	if !ok {
		return net.Listen("tcp", addr)
	}
	// A negative KeepAlive is needed to switch keepalive off: a zero
	// KeepAliveConfig alone leaves the Go default on.
	lc := net.ListenConfig{KeepAlive: -1}
	if cfg.Enable {
		lc = net.ListenConfig{KeepAliveConfig: cfg}
		log.Infof("testka: relay ws tcp keepalive idle=%s interval=%s count=%d", cfg.Idle, cfg.Interval, cfg.Count)
	} else {
		log.Infof("testka: relay ws tcp keepalive off")
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
