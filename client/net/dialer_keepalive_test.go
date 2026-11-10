package net

import (
	"testing"
	"time"
)

func TestTCPKeepAliveDialer(t *testing.T) {
	t.Run("stock without test heartbeat", func(t *testing.T) {
		t.Setenv("NB_TEST_TCP_KEEPALIVE_SEC", "")
		t.Setenv("NB_TEST_HB_DYNAMIC", "")
		d := tcpKeepAliveDialer()
		if d.KeepAlive != 0 || d.KeepAliveConfig.Enable {
			t.Fatalf("want Go default, got KeepAlive=%v config=%+v", d.KeepAlive, d.KeepAliveConfig)
		}
	})

	t.Run("twice the heartbeat period", func(t *testing.T) {
		t.Setenv("NB_TEST_TCP_KEEPALIVE_SEC", "")
		t.Setenv("NB_TEST_HB_DYNAMIC", "1")
		t.Setenv("NB_TEST_HB_PERIOD_SEC", "60")
		c := tcpKeepAliveDialer().KeepAliveConfig
		if !c.Enable || c.Idle != 120*time.Second || c.Interval != tcpKeepAliveInterval || c.Count != tcpKeepAliveProbes {
			t.Fatalf("unexpected config %+v", c)
		}
	})

	t.Run("env override wins", func(t *testing.T) {
		t.Setenv("NB_TEST_TCP_KEEPALIVE_SEC", "-1")
		t.Setenv("NB_TEST_HB_DYNAMIC", "1")
		d := tcpKeepAliveDialer()
		if d.KeepAlive != -time.Second || d.KeepAliveConfig.Enable {
			t.Fatalf("want override, got KeepAlive=%v config=%+v", d.KeepAlive, d.KeepAliveConfig)
		}
	})
}
