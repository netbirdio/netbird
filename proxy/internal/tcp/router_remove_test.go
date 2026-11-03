package tcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestRemoveRoutePreservesUnmatchedServiceConnections(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "SNI route on another host"
		if fallback {
			name = "fallback without SNI route"
		}
		t.Run(name, func(t *testing.T) {
			backend := startEchoTLS(t)
			router := NewPortRouter(log.StandardLogger(), func(_ types.AccountID) (types.DialContextFunc, error) {
				return (&net.Dialer{}).DialContext, nil
			})
			route := Route{Type: RouteTCP, ServiceID: "active", Target: backend.Addr().String()}
			if fallback {
				require.True(t, router.SetFallback(route), "the active service must own the fallback")
			} else {
				router.AddRoute("active.example.com", route)
			}
			router.AddRoute("other.example.com", Route{Type: RouteTCP, ServiceID: "other"})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() { _ = router.Serve(ctx, ln) }()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
				ServerName: "active.example.com", InsecureSkipVerify: true, //nolint:gosec
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			echo := func(message string) {
				t.Helper()
				require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
				_, err := conn.Write([]byte(message))
				require.NoError(t, err)
				got := make([]byte, len(message))
				_, err = io.ReadFull(conn, got)
				require.NoError(t, err)
				assert.Equal(t, message, string(got), "the existing relay must still deliver bytes")
			}
			echo("before removal")
			router.mu.RLock()
			relayCtx := router.svcCtxs["active"]
			router.mu.RUnlock()
			require.NotNil(t, relayCtx, "the established relay must have a cancellation context")
			for _, host := range []SNIHost{"missing.example.com", "other.example.com"} {
				router.RemoveRoute(host, "active")
				require.NoError(t, relayCtx.Err(), "an unmatched removal must not cancel an active relay")
				echo("after unmatched removal")
			}
			assert.Equal(t, []types.ServiceID{"other"}, router.RouteOwners("other.example.com"), "another service's route must survive")
			if fallback {
				router.RemoveFallback("active")
			} else {
				router.RemoveRoute("ACTIVE.EXAMPLE.COM.", "active")
			}
			assert.ErrorIs(t, relayCtx.Err(), context.Canceled, "removing the actual route must still revoke active relays")
		})
	}
}
