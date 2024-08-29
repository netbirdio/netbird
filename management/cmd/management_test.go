package cmd

import (
	"context"
	"os"
	"testing"
)

const (
	exampleConfig = `{	
		"Relay": {
		   "Address": "rels://relay.stage.npeer.io"
		},
		"HttpConfig": {
			"AuthAudience": "https://stageapp/",
			"AuthIssuer": "https://something.eu.auth0.com/",
			"OIDCConfigEndpoint": "https://something.eu.auth0.com/.well-known/openid-configuration"
		}
	}`
)

func Test_loadMgmtConfig(t *testing.T) {
	tmpFile, err := createConfig()
	if err != nil {
		t.Fatalf("failed to create config: %s", err)
	}

	cfg, err := loadMgmtConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load management config: %s", err)
	}
	if cfg.Relay == nil {
		t.Fatalf("config is nil")
	}
	if cfg.Relay.Address == "" {
		t.Fatalf("relay address is empty")
	}
}

func createConfig() (string, error) {
	tmpfile, err := os.CreateTemp("", "config.json")
	if err != nil {
		return "", err
	}
	_, err = tmpfile.Write([]byte(exampleConfig))
	if err != nil {
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}
