package dex

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProvider(t *testing.T) (*Provider, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "dex-connector-test-*")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s, err := (&sql.SQLite3{File: filepath.Join(tmpDir, "dex.db")}).Open(logger)
	require.NoError(t, err)

	return &Provider{storage: s, logger: logger}, func() {
		_ = s.Close()
		_ = os.RemoveAll(tmpDir)
	}
}

func TestBuildOIDCConnectorConfig_EntraSetsUserIDKey(t *testing.T) {
	cfg := &ConnectorConfig{
		ID:           "entra-test",
		Name:         "Entra",
		Type:         "entra",
		Issuer:       "https://login.microsoftonline.com/tid/v2.0",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	data, err := buildOIDCConnectorConfig(cfg, "https://example.com/oauth2/callback")
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "oid", m["userIDKey"], "entra connectors must default userIDKey to oid")
	assert.Equal(t, map[string]any{"email": "preferred_username"}, m["claimMapping"])
}

func TestBuildOIDCConnectorConfig_NonEntraDoesNotSetUserIDKey(t *testing.T) {
	// ensures the Entra userIDKey override does not leak into other OIDC providers,
	// which already use a stable sub claim.
	for _, typ := range []string{"oidc", "zitadel", "okta", "pocketid", "authentik", "keycloak", "adfs"} {
		t.Run(typ, func(t *testing.T) {
			data, err := buildOIDCConnectorConfig(&ConnectorConfig{Type: typ}, "https://example.com/oauth2/callback")
			require.NoError(t, err)
			var m map[string]any
			require.NoError(t, json.Unmarshal(data, &m))
			_, ok := m["userIDKey"]
			assert.False(t, ok, "%s connectors must not have userIDKey set", typ)
		})
	}
}

func TestUpdateConnector_PreservesCreateTimeDefaults(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	created, err := p.CreateConnector(ctx, &ConnectorConfig{
		ID:           "entra-test",
		Name:         "Entra",
		Type:         "entra",
		Issuer:       "https://login.microsoftonline.com/tid/v2.0",
		ClientID:     "client-id",
		ClientSecret: "old-secret",
		RedirectURI:  "https://example.com/oauth2/callback",
	})
	require.NoError(t, err)
	require.Equal(t, "entra-test", created.ID)

	// Rotate only the client secret.
	err = p.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "entra-test",
		Type:         "entra",
		ClientSecret: "new-secret",
	})
	require.NoError(t, err)

	conn, err := p.storage.GetConnector(ctx, "entra-test")
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(conn.Config, &m))

	assert.Equal(t, "new-secret", m["clientSecret"], "clientSecret should be rotated")
	assert.Equal(t, "client-id", m["clientID"], "clientID must survive (overlay should leave it alone)")
	assert.Equal(t, "https://login.microsoftonline.com/tid/v2.0", m["issuer"])
	assert.Equal(t, "oid", m["userIDKey"], "userIDKey must survive update")
	assert.Equal(t, map[string]any{"email": "preferred_username"}, m["claimMapping"], "claimMapping must survive update")
}

func TestUpdateConnector_DoesNotAddUserIDKeyToExistingConnector(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	// Seed a connector directly into storage without userIDKey
	preFixConfig, err := json.Marshal(map[string]any{
		"issuer":       "https://login.microsoftonline.com/tid/v2.0",
		"clientID":     "client-id",
		"clientSecret": "old-secret",
		"redirectURI":  "https://example.com/oauth2/callback",
		"scopes":       []string{"openid", "profile", "email"},
		"claimMapping": map[string]string{"email": "preferred_username"},
	})
	require.NoError(t, err)

	require.NoError(t, p.storage.CreateConnector(ctx, storage.Connector{
		ID:     "entra-prefix",
		Type:   "oidc",
		Name:   "Entra",
		Config: preFixConfig,
	}))

	// Rotate client secret via UpdateConnector.
	err = p.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "entra-prefix",
		Type:         "entra",
		ClientSecret: "new-secret",
	})
	require.NoError(t, err)

	conn, err := p.storage.GetConnector(ctx, "entra-prefix")
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(conn.Config, &m))

	assert.Equal(t, "new-secret", m["clientSecret"])
	_, has := m["userIDKey"]
	assert.False(t, has, "userIDKey must not be auto-added to a connector that did not have it before")
}

func TestUpdateConnector_RejectsTypeChange(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	_, err := p.CreateConnector(ctx, &ConnectorConfig{
		ID:           "entra-test",
		Name:         "Entra",
		Type:         "entra",
		Issuer:       "https://login.microsoftonline.com/tid/v2.0",
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURI:  "https://example.com/oauth2/callback",
	})
	require.NoError(t, err)

	// Attempt to switch the connector to okta.
	err = p.UpdateConnector(ctx, &ConnectorConfig{
		ID:   "entra-test",
		Type: "okta",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector type change not allowed")

	// stored connector type/config unchanged after the rejected update.
	conn, err := p.storage.GetConnector(ctx, "entra-test")
	require.NoError(t, err)
	assert.Equal(t, "oidc", conn.Type)
	var m map[string]any
	require.NoError(t, json.Unmarshal(conn.Config, &m))
	assert.Equal(t, "oid", m["userIDKey"])
}

func TestUpdateConnector_AllowsSameTypeUpdate(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	_, err := p.CreateConnector(ctx, &ConnectorConfig{
		ID:           "entra-test",
		Name:         "Entra",
		Type:         "entra",
		Issuer:       "https://login.microsoftonline.com/old/v2.0",
		ClientID:     "client-id",
		ClientSecret: "secret",
		RedirectURI:  "https://example.com/oauth2/callback",
	})
	require.NoError(t, err)

	err = p.UpdateConnector(ctx, &ConnectorConfig{
		ID:     "entra-test",
		Type:   "entra",
		Issuer: "https://login.microsoftonline.com/new/v2.0",
	})
	require.NoError(t, err)

	conn, err := p.storage.GetConnector(ctx, "entra-test")
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(conn.Config, &m))
	assert.Equal(t, "https://login.microsoftonline.com/new/v2.0", m["issuer"])
}
