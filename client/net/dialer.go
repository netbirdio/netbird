package net

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Dialer extends the standard net.Dialer with the ability to execute hooks before
// and after connections. This can be used to bypass the VPN for connections using this dialer.
type Dialer struct {
	*net.Dialer
}

// NewDialer returns a customized net.Dialer with overridden Control method
func NewDialer() *Dialer {
	dialer := &Dialer{
		Dialer: &net.Dialer{KeepAlive: localTestEnvSeconds("NB_TEST_TCP_KEEPALIVE_SEC", 0)},
	}
	dialer.init()
	return dialer
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
