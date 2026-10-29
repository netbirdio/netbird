package store

import (
	"context"
	"testing"
	"time"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveProxy_EnforcesAccountIDMatch(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "", func(t *testing.T, engine string, store Store) {
		ctx := context.Background()

		for _, proxy := range []*rpproxy.Proxy{
			{
				ID:        "proxy-no-account",
				SessionID: "sesssion-id-1",
			},
			{
				ID:        "proxy-account-id-1",
				AccountID: new("account-id-1"),
				SessionID: "sesssion-id-2",
			},
			{
				ID:             "proxy-account-id-2",
				ConnectedAt:    new(time.Now()),
				DisconnectedAt: new(time.Now()),
				Capabilities:   rpproxy.Capabilities{SupportsCustomPorts: new(true), RequireSubdomain: new(true), SupportsCrowdsec: new(true)},
			},
		} {
			err := store.SaveProxy(ctx, proxy)
			assert.NoError(t, err)
		}

		tests := []struct {
			description string
			proxy       rpproxy.Proxy
			err         *status.Type
		}{
			{
				description: "updating proxy without id",
				proxy:       rpproxy.Proxy{AccountID: new("some-account-id-2")},
				err:         new(status.InvalidArgument),
			},
			{
				description: "updating nullable fields",
				proxy: rpproxy.Proxy{
					ID:             "proxy-account-id-2",
					ConnectedAt:    nil,
					DisconnectedAt: nil,
					Capabilities:   rpproxy.Capabilities{SupportsCustomPorts: nil, RequireSubdomain: nil, SupportsCrowdsec: nil}},
			},
			{
				description: "updating proxy without account id",
				proxy:       rpproxy.Proxy{ID: "proxy-no-account", AccountID: new("some-account-id")},
				err:         new(status.PermissionDenied),
			},
			{
				description: "overwriting proxy with a different account id when account id is nil",
				proxy:       rpproxy.Proxy{ID: "proxy-account-id-1"},
				err:         new(status.PermissionDenied),
			},
			{
				description: "overwriting proxy without account id when account id is not nil",
				proxy:       rpproxy.Proxy{ID: "proxy-no-account", SessionID: "session-id-1-1"},
			},
			{
				description: "updating proxy with an account id",
				proxy:       rpproxy.Proxy{ID: "proxy-account-id-1", AccountID: new("account-id-1"), SessionID: "session-id-2-2"},
			},
			{
				description: "overwriting proxy with a different account id",
				proxy:       rpproxy.Proxy{ID: "proxy-account-id-1", AccountID: new("some-account-id")},
				err:         new(status.PermissionDenied),
			},
			{
				description: "removing account id from proxy",
				proxy:       rpproxy.Proxy{ID: "proxy-account-id-1"},
				err:         new(status.PermissionDenied),
			},
		}

		for _, tt := range tests {
			t.Run(tt.description, func(t *testing.T) {
				copy := tt.proxy
				err := store.SaveProxy(ctx, &copy)
				if tt.err != nil {
					statusError, isStError := status.FromError(err)
					assert.True(t, isStError)
					require.NotNil(t, statusError)
					assert.Equal(t, *tt.err, statusError.Type())
				} else {
					assert.NoError(t, err)
					var p rpproxy.Proxy
					err := store.(*SqlStore).db.Where("id = ?", tt.proxy.ID).Omit("created_at", "updated_at", "last_seen").First(&p).Error
					assert.NoError(t, err)
					assert.Equal(t, tt.proxy, p)
				}
			})
		}
	})
}
