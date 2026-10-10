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

func TestGenericOIDCOptionsRoundTrip(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	claim := "iserv:groups"
	getUserInfo := true
	_, err := p.CreateConnector(ctx, &ConnectorConfig{
		ID: "school", Name: "IServ", Type: "oidc",
		Issuer: "https://idp.example.com", ClientID: "client", ClientSecret: "secret",
		RedirectURI:      "https://example.com/oauth2/callback",
		AdditionalScopes: []string{"iserv:groups", "email", "iserv:groups"}, GroupsClaim: &claim, GetUserInfo: &getUserInfo,
	})
	require.NoError(t, err)

	stored, err := p.storage.GetConnector(ctx, "school")
	require.NoError(t, err)
	var config map[string]any
	require.NoError(t, json.Unmarshal(stored.Config, &config))
	assert.Equal(t, []any{"openid", "profile", "email", "iserv:groups"}, config["scopes"])
	assert.Equal(t, map[string]any{"groups": "iserv:groups"}, config["claimMapping"])
	assert.Equal(t, true, config["overrideClaimMapping"], "the selected claim must win over a standard groups claim")
	assert.Equal(t, true, config["insecureEnableGroups"])
	assert.Equal(t, true, config["getUserInfo"])

	read, err := p.GetConnector(ctx, "school")
	require.NoError(t, err)
	assert.Equal(t, []string{"iserv:groups"}, read.AdditionalScopes)
	require.NotNil(t, read.GroupsClaim)
	assert.Equal(t, claim, *read.GroupsClaim)
	require.NotNil(t, read.GetUserInfo)
	assert.True(t, *read.GetUserInfo)

	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{ID: "school", Type: "oidc", ClientSecret: "rotated"}))
	read, err = p.GetConnector(ctx, "school")
	require.NoError(t, err)
	assert.Equal(t, []string{"iserv:groups"}, read.AdditionalScopes)
	require.NotNil(t, read.GroupsClaim)
	assert.Equal(t, claim, *read.GroupsClaim)
	require.NotNil(t, read.GetUserInfo)
	assert.True(t, *read.GetUserInfo)

	empty := ""
	getUserInfo = false
	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{
		ID: "school", Type: "oidc", AdditionalScopes: []string{}, GroupsClaim: &empty, GetUserInfo: &getUserInfo,
	}))
	stored, err = p.storage.GetConnector(ctx, "school")
	require.NoError(t, err)
	config = nil
	require.NoError(t, json.Unmarshal(stored.Config, &config))
	assert.Equal(t, []any{"openid", "profile", "email"}, config["scopes"])
	assert.NotContains(t, config, "claimMapping")
	assert.NotContains(t, config, "overrideClaimMapping")
	assert.Equal(t, false, config["getUserInfo"])
	read, err = p.GetConnector(ctx, "school")
	require.NoError(t, err)
	assert.Empty(t, read.AdditionalScopes)
	assert.Nil(t, read.GroupsClaim)
	require.NotNil(t, read.GetUserInfo)
	assert.False(t, *read.GetUserInfo)

	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{ID: "school", Type: "oidc", GroupsClaim: &claim}))
	stored, err = p.storage.GetConnector(ctx, "school")
	require.NoError(t, err)
	config = nil
	require.NoError(t, json.Unmarshal(stored.Config, &config))
	assert.Equal(t, true, config["overrideClaimMapping"])
}

func TestNonGenericOIDCOptionsDoNotChangeProviderDefaults(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()
	empty := ""
	getUserInfo := false
	_, err := p.CreateConnector(ctx, &ConnectorConfig{
		ID: "okta-test", Type: "okta", AdditionalScopes: []string{}, GroupsClaim: &empty, GetUserInfo: &getUserInfo,
	})
	require.NoError(t, err)
	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{
		ID: "okta-test", Type: "okta", AdditionalScopes: []string{}, GroupsClaim: &empty, GetUserInfo: &getUserInfo,
	}))
	stored, err := p.storage.GetConnector(ctx, "okta-test")
	require.NoError(t, err)
	var config map[string]any
	require.NoError(t, json.Unmarshal(stored.Config, &config))
	assert.Equal(t, []any{"openid", "profile", "email", "groups"}, config["scopes"])
	assert.NotContains(t, config, "claimMapping")

	_, err = p.CreateConnector(ctx, &ConnectorConfig{
		ID: "okta-other", Type: "okta", AdditionalScopes: []string{"iserv:groups"},
	})
	require.Error(t, err)
	require.Error(t, p.UpdateConnector(ctx, &ConnectorConfig{
		ID: "okta-test", Type: "okta", GroupsClaim: new(string),
		AdditionalScopes: []string{"iserv:groups"},
	}))
	getUserInfo = true
	require.Error(t, p.UpdateConnector(ctx, &ConnectorConfig{ID: "okta-test", Type: "okta", GetUserInfo: &getUserInfo}))
}

func TestGroupsClaimDoesNotChangeExistingEmailMappingPrecedence(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()
	oldConfig, err := json.Marshal(map[string]any{
		"scopes":       []string{"openid", "profile", "email"},
		"claimMapping": map[string]string{"email": "preferred_username"},
	})
	require.NoError(t, err)
	require.NoError(t, p.storage.CreateConnector(ctx, storage.Connector{
		ID: "generic", Type: "oidc", Config: oldConfig,
	}))
	claim := "iserv:groups"
	err = p.UpdateConnector(ctx, &ConnectorConfig{ID: "generic", Type: "oidc", GroupsClaim: &claim})
	require.ErrorIs(t, err, ErrIncompatibleClaimMapping)
	assert.ErrorContains(t, err, "email")
	stored, err := p.storage.GetConnector(ctx, "generic")
	require.NoError(t, err)
	assert.JSONEq(t, string(oldConfig), string(stored.Config))
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
