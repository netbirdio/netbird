package ws

import (
	"net"
	"testing"
	"time"
)

func TestTestKeepaliveConfig(t *testing.T) {
	tests := []struct {
		name   string
		val    string
		wantOK bool
		want   net.KeepAliveConfig
	}{
		{name: "unset", val: "", wantOK: false},
		{name: "invalid", val: "abc", wantOK: false},
		{name: "zero", val: "0", wantOK: false},
		{name: "below minus one", val: "-2", wantOK: false},
		{name: "off", val: "-1", wantOK: true, want: net.KeepAliveConfig{Enable: false}},
		{name: "seconds", val: "120", wantOK: true, want: net.KeepAliveConfig{
			Enable:   true,
			Idle:     120 * time.Second,
			Interval: 15 * time.Second,
			Count:    3,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := testKeepaliveConfig(func(string) string { return tt.val })
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("config = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestListenTCPWithTestKeepalive(t *testing.T) {
	for _, val := range []string{"", "-1", "120"} {
		t.Run("env="+val, func(t *testing.T) {
			t.Setenv(envServerTCPKASec, val)
			ln, err := listenTCP("127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			done := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err == nil {
					_ = c.Close()
				}
				done <- err
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = c.Close()
			if err := <-done; err != nil {
				t.Fatalf("accept: %v", err)
			}
		})
	}
}
