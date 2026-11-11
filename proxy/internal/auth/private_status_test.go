package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func notInGroup(hasPrivateAccess bool) *proto.ValidateTunnelPeerResponse {
	return &proto.ValidateTunnelPeerResponse{DeniedReason: "not_in_group", HasPrivateAccess: hasPrivateAccess}
}

// TestPrivateRefusalStatus pins the status a private service refuses each kind
// of caller with. Only the status changes: no refused request reaches the
// upstream, and the allowed one still does.
func TestPrivateRefusalStatus(t *testing.T) {
	tests := []struct {
		name         string
		resp         *proto.ValidateTunnelPeerResponse
		rpcErr       error
		overlay      bool
		agentNetwork bool
		filter       *restrict.Filter
		callerAcct   types.AccountID
		wantStatus   int
	}{
		{
			name:       "caller outside the overlay",
			resp:       &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "another account's peer",
			resp:       &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"},
			overlay:    true,
			callerAcct: "acct-other",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "account peer with access to another private service",
			resp:       notInGroup(true),
			overlay:    true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "account peer with no private access",
			resp:       notInGroup(false),
			overlay:    true,
			wantStatus: http.StatusNotFound,
		},
		{
			name:         "agent network peer without a policy allowance",
			resp:         notInGroup(false),
			overlay:      true,
			agentNetwork: true,
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "agent network caller outside the overlay",
			resp:         notInGroup(false),
			agentNetwork: true,
			wantStatus:   http.StatusNotFound,
		},
		{
			name:       "peer whose owner is blocked",
			resp:       &proto.ValidateTunnelPeerResponse{DeniedReason: "user_blocked"},
			overlay:    true,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "management unreachable",
			rpcErr:     errors.New("unavailable"),
			overlay:    true,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "account peer refused by an IP restriction",
			resp:       &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"},
			overlay:    true,
			filter:     restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}}),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "allowed peer",
			resp:       &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"},
			overlay:    true,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &stubSessionValidator{
				respErr: tt.rpcErr,
				respFn:  func(*proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse { return tt.resp },
			}
			mw := NewMiddleware(log.StandardLogger(), validator, nil)
			require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", tt.filter, true, nil, WithAgentNetwork(tt.agentNetwork, false)))

			reached := false
			handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			cd := proxy.NewCapturedData("")
			cd.SetClientIP(testTunnelIP)
			if tt.callerAcct != "" {
				cd.SetAccountID(tt.callerAcct)
			}
			ctx := proxy.WithCapturedData(t.Context(), cd)
			if tt.overlay {
				ctx = WithTunnelLookup(ctx, acceptAllLookup)
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://"+testServerHost+"/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code, "refusal status")
			assert.Equal(t, tt.wantStatus == http.StatusOK, reached, "only the allowed request may reach the upstream")
			if tt.wantStatus != http.StatusOK {
				assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "a refusal is attributed to auth")
				assert.Equal(t, "close", rec.Header().Get("Connection"), "a private refusal closes the connection")
			}
		})
	}
}
