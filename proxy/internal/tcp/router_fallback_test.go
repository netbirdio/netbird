package tcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestSetFallbackPreservesUnchangedServiceConnections(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		name := "without restrictions"
		if restricted {
			name = "rebuilt equivalent restrictions"
		}
		t.Run(name, func(t *testing.T) {
			backend := startEchoTLS(t)
			router := NewPortRouter(log.StandardLogger(), func(_ types.AccountID) (types.DialContextFunc, error) {
				return (&net.Dialer{}).DialContext, nil
			})
			route := Route{Type: RouteTCP, ServiceID: "active", Target: backend.Addr().String()}
			filterConfig := restrict.FilterConfig{AllowedCIDRs: []string{"127.0.0.0/8"}}
			if restricted {
				route.Filter = restrict.ParseFilter(filterConfig)
			}
			require.True(t, router.SetFallback(route))
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() { _ = router.Serve(ctx, ln) }()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
				ServerName: "fallback.example.com", InsecureSkipVerify: true, //nolint:gosec
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
			echo("before registration")
			router.mu.RLock()
			relayCtx := router.svcCtxs["active"]
			router.mu.RUnlock()
			require.NotNil(t, relayCtx)
			if restricted {
				route.Filter = restrict.ParseFilter(filterConfig)
			}
			require.True(t, router.SetFallback(route))
			require.NoError(t, relayCtx.Err(), "registering an unchanged fallback must not cancel active relays")
			echo("after registration")

			route.Target = "127.0.0.1:1"
			require.True(t, router.SetFallback(route))
			assert.ErrorIs(t, relayCtx.Err(), context.Canceled, "changing the target must revoke active relays")
		})
	}
}

func TestSetFallbackChangedRestrictionsCancelService(t *testing.T) {
	changes := map[string]func(*restrict.Filter){
		"allowed CIDRs":     func(f *restrict.Filter) { f.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
		"blocked CIDRs":     func(f *restrict.Filter) { f.BlockedCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} },
		"allowed countries": func(f *restrict.Filter) { f.AllowedCountries = []string{"DE"} },
		"blocked countries": func(f *restrict.Filter) { f.BlockedCountries = []string{"US"} },
		"CrowdSec mode":     func(f *restrict.Filter) { f.CrowdSecMode = restrict.CrowdSecEnforce },
		"CrowdSec checker":  func(f *restrict.Filter) { f.CrowdSec = &fallbackChecker{} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			router := NewPortRouter(log.StandardLogger(), nil)
			route := Route{Type: RouteTCP, ServiceID: "active", Filter: &restrict.Filter{}}
			require.True(t, router.SetFallback(route))
			router.mu.Lock()
			relayCtx := router.getOrCreateServiceCtxLocked(context.Background(), route.ServiceID)
			router.mu.Unlock()
			updated := *route.Filter
			change(&updated)
			route.Filter = &updated
			require.True(t, router.SetFallback(route))
			assert.ErrorIs(t, relayCtx.Err(), context.Canceled)
		})
	}
}

func TestSameFilterCrowdSecIdentity(t *testing.T) {
	checker := &fallbackChecker{}
	filter := &restrict.Filter{CrowdSec: checker, CrowdSecMode: restrict.CrowdSecObserve}
	assert.True(t, sameFilter(filter, &restrict.Filter{CrowdSec: checker, CrowdSecMode: restrict.CrowdSecObserve}))
	assert.False(t, sameFilter(filter, &restrict.Filter{CrowdSec: &fallbackChecker{}, CrowdSecMode: restrict.CrowdSecObserve}))
	uncomparable := &restrict.Filter{CrowdSec: fallbackChecker{}, CrowdSecMode: restrict.CrowdSecObserve}
	assert.False(t, sameFilter(uncomparable, &restrict.Filter{CrowdSec: fallbackChecker{}, CrowdSecMode: restrict.CrowdSecObserve}))
}

type fallbackChecker []restrict.CrowdSecDecision

func (fallbackChecker) CheckIP(netip.Addr) *restrict.CrowdSecDecision { return nil }
func (fallbackChecker) Ready() bool                                   { return true }
