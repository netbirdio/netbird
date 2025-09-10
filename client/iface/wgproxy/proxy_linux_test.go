//go:build linux && !android

package wgproxy

import (
	"context"
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
)

func TestProxyCloseByRemoteConnEBPF(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("Skipping test as it requires root privileges")
	}
	ctx := context.Background()

	ebpfProxy := ebpf.NewWGEBPFProxy(51831, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		t.Fatalf("failed to initialize ebpf proxy: %s", err)
	}

	defer func() {
		if err := ebpfProxy.Free(); err != nil {
			t.Errorf("failed to free ebpf proxy: %s", err)
		}
	}()

	tests := []struct {
		name  string
		proxy Proxy
	}{
		{
			name: "ebpf proxy",
			proxy: &ebpf.ProxyWrapper{
				WgeBPFProxy: ebpfProxy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relayedConn := newMockConn()
			err := tt.proxy.AddTurnConn(ctx, nil, relayedConn)
			if err != nil {
				t.Errorf("error: %v", err)
			}

			_ = relayedConn.Close()
			if err := tt.proxy.CloseConn(); err != nil {
				t.Errorf("error: %v", err)
			}
		})
	}
}
