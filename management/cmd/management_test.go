package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/management/grpc"
)

const (
	exampleConfig = `{
	  "Relay": {
		"Addresses": [
		  "rel://192.168.100.1:8085",
		  "rel://192.168.100.1:8086"
		],
		"CredentialsTTL": "12h0m0s",
		"Secret": "8f7e9d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8"
	  },
	  "HttpConfig": {
		"AuthAudience": "https://stageapp/",
		"AuthIssuer": "https://something.eu.auth0.com/",
		"OIDCConfigEndpoint": "https://something.eu.auth0.com/.well-known/openid-configuration"
	  },
	  "HighestSupportedSyncMessageVersion": 1,
	  "PerAccountHighestSupportedSyncMessageVersion": {
	    "1": 0,
		"2": 1
	  }
	}`
)

func Test_LoadMgmtConfig(t *testing.T) {
	tmpFile, err := createConfig(exampleConfig)
	assert.NoError(t, err)

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	assert.NoError(t, err)
	assert.NotEmpty(t, cfg.Relay)
	assert.NotEmpty(t, cfg.Relay.Addresses)
	assert.Equal(t, int(grpc.ComponentNetworkMap), *cfg.HighestSupportedSyncMessageVersion)
	assert.Equal(t, map[string]int{"1": int(grpc.Base), "2": int(grpc.ComponentNetworkMap)}, cfg.PerAccountHighestSupportedSyncMessageVersion)
}

func Test_LoadMgmtConfig_Empty(t *testing.T) {
	tmpFile, err := createConfig(`{
		"HttpConfig": {
			"AuthAudience": "https://stageapp/",
			"AuthIssuer": "https://something.eu.auth0.com/",
			"OIDCConfigEndpoint": "https://something.eu.auth0.com/.well-known/openid-configuration"
		}
	}`)
	assert.NoError(t, err)

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	assert.NoError(t, err)
	assert.Nil(t, cfg.HighestSupportedSyncMessageVersion)
	assert.Nil(t, cfg.PerAccountHighestSupportedSyncMessageVersion)
}

func Test_LoadMgmtConfig_WithoutHttpConfig(t *testing.T) {
	tmpFile, err := createConfig(`{
		"Datadir": "/tmp/netbird-test"
	}`)
	require.NoError(t, err)

	cfg, err := LoadMgmtConfig(context.Background(), tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestApplyEmbeddedIdPConfigRequiresSingleAccountDomain(t *testing.T) {
	previousDomain := mgmtSingleAccModeDomain
	previousDisabled := disableSingleAccMode
	t.Cleanup(func() {
		mgmtSingleAccModeDomain = previousDomain
		disableSingleAccMode = previousDisabled
	})

	mgmtSingleAccModeDomain = ""
	disableSingleAccMode = false
	cfg := &nbconfig.Config{
		EmbeddedIdP: &idp.EmbeddedIdPConfig{Enabled: true},
	}
	require.ErrorContains(t, ApplyEmbeddedIdPConfig(context.Background(), cfg), "embedded IdP requires single account mode")
}

// A config without an HttpConfig section is valid with the embedded IdP, so the
// TLS flags must not assume the section exists.
func TestApplyCommandLineOverridesWithoutHttpConfig(t *testing.T) {
	previousDomain, previousCertFile, previousCertKey := mgmtLetsencryptDomain, certFile, certKey
	t.Cleanup(func() {
		mgmtLetsencryptDomain, certFile, certKey = previousDomain, previousCertFile, previousCertKey
	})

	tests := []struct {
		name     string
		domain   string
		certFile string
		certKey  string
		want     nbconfig.HttpServerConfig
	}{
		{
			name:   "letsencrypt domain",
			domain: "mgmt.example.com",
			want:   nbconfig.HttpServerConfig{LetsEncryptDomain: "mgmt.example.com"},
		},
		{
			name:     "certificate files",
			certFile: "/etc/netbird/tls/tls.crt",
			certKey:  "/etc/netbird/tls/tls.key",
			want:     nbconfig.HttpServerConfig{CertFile: "/etc/netbird/tls/tls.crt", CertKey: "/etc/netbird/tls/tls.key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgmtLetsencryptDomain, certFile, certKey = tt.domain, tt.certFile, tt.certKey
			cfg := &nbconfig.Config{}

			ApplyCommandLineOverrides(cfg)

			require.NotNil(t, cfg.HttpConfig, "HttpConfig should be created for the TLS flags")
			assert.Equal(t, tt.want, *cfg.HttpConfig, "HttpConfig should carry only the flag values")
		})
	}

	t.Run("no TLS flags", func(t *testing.T) {
		mgmtLetsencryptDomain, certFile, certKey = "", "", ""
		cfg := &nbconfig.Config{}

		ApplyCommandLineOverrides(cfg)

		assert.Nil(t, cfg.HttpConfig, "HttpConfig should stay unset so the embedded IdP does not warn about it")
	})
}

func createConfig(config string) (string, error) {
	tmpfile, err := os.CreateTemp("", "config.json")
	if err != nil {
		return "", err
	}
	_, err = tmpfile.Write([]byte(config))
	if err != nil {
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}
