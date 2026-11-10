package net

import (
	"net"
	"os"
	"strconv"
	"time"

	"github.com/netbirdio/netbird/shared/testhb"
)

// Dialer extends the standard net.Dialer with the ability to execute hooks before
// and after connections. This can be used to bypass the VPN for connections using this dialer.
type Dialer struct {
	*net.Dialer
}

// NewDialer returns a customized net.Dialer with overridden Control method
func NewDialer() *Dialer {
	dialer := &Dialer{
		Dialer: tcpKeepAliveDialer(),
	}
	dialer.init()
	return dialer
}

// tcpKeepAliveProbes is how many unanswered probes close a dead connection.
const tcpKeepAliveProbes = 3

// tcpKeepAliveInterval is the time between probes once the idle time has passed.
const tcpKeepAliveInterval = 15 * time.Second

// tcpKeepAliveDialer returns the base dialer with TCP keepalive set for the
// test heartbeat. NB_TEST_TCP_KEEPALIVE_SEC wins when set. With the test
// heartbeat on, the idle time is twice the period: heartbeats and their ACKs
// keep the connection from going idle that long, so no probe is sent on a
// live connection, and a dead one is closed after about 2 periods plus 45 s.
// Without the test heartbeat the Go default stays.
func tcpKeepAliveDialer() *net.Dialer {
	if v := os.Getenv("NB_TEST_TCP_KEEPALIVE_SEC"); v != "" {
		return &net.Dialer{KeepAlive: localTestEnvSeconds("NB_TEST_TCP_KEEPALIVE_SEC", 0)}
	}
	period, ok := testhb.ClientPeriod()
	if !ok {
		return &net.Dialer{}
	}
	return &net.Dialer{KeepAliveConfig: net.KeepAliveConfig{
		Enable:   true,
		Idle:     2 * period,
		Interval: tcpKeepAliveInterval,
		Count:    tcpKeepAliveProbes,
	}}
}

// LOCAL TEST (battery measurement, never push): duration override in seconds from env.
// Empty or unparsable keeps def; a negative value is passed through (disables net.Dialer keepalive).
func localTestEnvSeconds(key string, def time.Duration) time.Duration {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return def
	}
	return time.Duration(v) * time.Second
}
