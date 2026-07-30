package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/netbirdio/netbird/shared/management/grpc"
	"github.com/stretchr/testify/assert"
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
