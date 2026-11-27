package dex

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/netbirdio/dex/storage"
	"github.com/netbirdio/dex/storage/sql"
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

func TestUpdateConnector_LegacyEmptyResourceVersion(t *testing.T) {
	ctx := context.Background()
	p, cleanup := newTestProvider(t)
	defer cleanup()

	cfgData, err := json.Marshal(map[string]any{
		"issuer":       "https://idp.example.com",
		"clientID":     "client-id",
		"clientSecret": "secret-1",
		"redirectURI":  "https://example.com/oauth2/callback",
	})
	require.NoError(t, err)

	// Simulate a connector created before ResourceVersion was populated.
	require.NoError(t, p.storage.CreateConnector(ctx, storage.Connector{
		ID:              "legacy-oidc",
		Type:            "oidc",
		Name:            "Legacy OIDC",
		ResourceVersion: "",
		Config:          cfgData,
	}))

	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "legacy-oidc",
		Type:         "oidc",
		ClientSecret: "secret-2",
	}))

	conn, err := p.storage.GetConnector(ctx, "legacy-oidc")
	require.NoError(t, err)
	assert.Equal(t, "1", conn.ResourceVersion)

	require.NoError(t, p.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "legacy-oidc",
		Type:         "oidc",
		ClientSecret: "secret-3",
	}))

	conn, err = p.storage.GetConnector(ctx, "legacy-oidc")
	require.NoError(t, err)
	assert.Equal(t, "2", conn.ResourceVersion)
}

func TestUpdateConnector_ReloadsCachedConnectorSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	require.NoError(t, err)

	var (
		mu              sync.Mutex
		receivedSecrets []string
		upstreamURL     string
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 upstreamURL,
				"authorization_endpoint": upstreamURL + "/authorize",
				"token_endpoint":         upstreamURL + "/token",
				"jwks_uri":               upstreamURL + "/jwks",
				"response_types_supported": []string{
					"code",
				},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
		case "/authorize":
			q := r.URL.Query()
			redirectURL, parseErr := url.Parse(q.Get("redirect_uri"))
			if parseErr != nil {
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
			rq := redirectURL.Query()
			rq.Set("code", "auth-code")
			rq.Set("state", q.Get("state"))
			redirectURL.RawQuery = rq.Encode()
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		case "/token":
			if parseErr := r.ParseForm(); parseErr != nil {
				t.Errorf("parse token form: %v", parseErr)
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
			_, secret, hasBasic := r.BasicAuth()
			if !hasBasic {
				secret = r.FormValue("client_secret")
			}
			mu.Lock()
			receivedSecrets = append(receivedSecrets, secret)
			mu.Unlock()

			now := time.Now()
			claims, marshalErr := json.Marshal(map[string]any{
				"iss":   upstreamURL,
				"sub":   "user-123",
				"aud":   "client-id",
				"email": "alice@example.com",
				"name":  "Alice Example",
				"iat":   now.Unix(),
				"exp":   now.Add(5 * time.Minute).Unix(),
			})
			if marshalErr != nil {
				t.Errorf("marshal claims: %v", marshalErr)
				http.Error(w, marshalErr.Error(), http.StatusInternalServerError)
				return
			}

			jwsObj, signErr := signer.Sign(claims)
			if signErr != nil {
				t.Errorf("sign claims: %v", signErr)
				http.Error(w, signErr.Error(), http.StatusInternalServerError)
				return
			}
			idToken, serErr := jwsObj.CompactSerialize()
			if serErr != nil {
				t.Errorf("serialize id_token: %v", serErr)
				http.Error(w, serErr.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-tok",
				"token_type":   "Bearer",
				"expires_in":   300,
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	upstreamURL = upstream.URL

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dexURL := "http://" + ln.Addr().String()

	provider, err := NewProvider(ctx, &Config{
		Issuer:  dexURL,
		Port:    ln.Addr().(*net.TCPAddr).Port,
		DataDir: t.TempDir(),
	})
	require.NoError(t, err)
	defer func() {
		if closeErr := provider.storage.Close(); closeErr != nil {
			t.Errorf("close provider storage: %v", closeErr)
		}
	}()

	dexHTTP := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: provider.dexServer},
	}
	dexHTTP.Start()
	defer dexHTTP.Close()

	require.NoError(t, provider.storage.CreateClient(ctx, storage.Client{
		ID:           "netbird-client",
		Public:       true,
		RedirectURIs: []string{"http://127.0.0.1/cb"},
	}))

	_, err = provider.CreateConnector(ctx, &ConnectorConfig{
		ID:           "oidc-rotate",
		Name:         "OIDC Rotate",
		Type:         "oidc",
		Issuer:       upstreamURL,
		ClientID:     "client-id",
		ClientSecret: "secret-a",
		RedirectURI:  dexURL + "/oauth2/callback",
	})
	require.NoError(t, err)

	conn, err := provider.storage.GetConnector(ctx, "oidc-rotate")
	require.NoError(t, err)
	assert.Equal(t, "1", conn.ResourceVersion)

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == "127.0.0.1" && req.URL.Path == "/cb" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	runAuthFlow := func(state string) {
		authURL := dexURL + "/oauth2/auth?client_id=netbird-client&redirect_uri=" +
			url.QueryEscape("http://127.0.0.1/cb") +
			"&response_type=code&scope=" + url.QueryEscape("openid profile email") +
			"&state=" + state + "&connector_id=oidc-rotate"

		resp, reqErr := httpClient.Get(authURL)
		require.NoError(t, reqErr)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		loc := resp.Header.Get("Location")
		require.Contains(t, loc, "http://127.0.0.1/cb")
		require.Contains(t, loc, "code=")
	}

	// Flow 1: warms Dex's in-memory connector cache with secret-a.
	runAuthFlow("state-1")

	// Rotate secret-a -> secret-b without restarting the provider.
	require.NoError(t, provider.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "oidc-rotate",
		Type:         "oidc",
		ClientSecret: "secret-b",
	}))
	conn, err = provider.storage.GetConnector(ctx, "oidc-rotate")
	require.NoError(t, err)
	assert.Equal(t, "2", conn.ResourceVersion)

	// Flow 2: must reload connector and use secret-b.
	runAuthFlow("state-2")

	// Rotate secret-b -> secret-c and verify repeated rotation.
	require.NoError(t, provider.UpdateConnector(ctx, &ConnectorConfig{
		ID:           "oidc-rotate",
		Type:         "oidc",
		ClientSecret: "secret-c",
	}))
	conn, err = provider.storage.GetConnector(ctx, "oidc-rotate")
	require.NoError(t, err)
	assert.Equal(t, "3", conn.ResourceVersion)

	runAuthFlow("state-3")

	// Delete and recreate the same connector ID to verify CreateConnector/DeleteConnector
	// invalidate Dex's cached connector entry.
	require.NoError(t, provider.DeleteConnector(ctx, "oidc-rotate"))
	_, err = provider.CreateConnector(ctx, &ConnectorConfig{
		ID:           "oidc-rotate",
		Name:         "OIDC Rotate",
		Type:         "oidc",
		Issuer:       upstreamURL,
		ClientID:     "client-id",
		ClientSecret: "secret-d",
		RedirectURI:  dexURL + "/oauth2/callback",
	})
	require.NoError(t, err)

	runAuthFlow("state-4")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"secret-a", "secret-b", "secret-c", "secret-d"}, receivedSecrets)
}
