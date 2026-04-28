package legoclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/credentials/secretpayload"
)

func TestBuildProviderUnknownName(t *testing.T) {
	_, err := BuildProvider("nope", map[string]string{"auth_token": "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown DNS provider")
}

func TestBuildCloudflare(t *testing.T) {
	t.Run("modern auth_token field", func(t *testing.T) {
		_, err := BuildProvider("cloudflare", map[string]string{"auth_token": "cf_token"})
		require.NoError(t, err)
	})
	t.Run("legacy fallback", func(t *testing.T) {
		_, err := BuildProvider("cloudflare", map[string]string{secretpayload.LegacyKey: "cf_token"})
		require.NoError(t, err)
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := BuildProvider("cloudflare", map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth_token")
	})
}

func TestBuildRoute53(t *testing.T) {
	t.Run("required fields", func(t *testing.T) {
		_, err := BuildProvider("route53", map[string]string{
			"access_key_id":     "AKIAEXAMPLE",
			"secret_access_key": "shh",
		})
		require.NoError(t, err)
	})
	t.Run("optional region honored", func(t *testing.T) {
		_, err := BuildProvider("route53", map[string]string{
			"access_key_id":     "AKIAEXAMPLE",
			"secret_access_key": "shh",
			"region":            "us-west-2",
			"hosted_zone_id":    "Z123456",
			"session_token":     "AQoDExample",
		})
		require.NoError(t, err)
	})
	t.Run("missing access_key_id", func(t *testing.T) {
		_, err := BuildProvider("route53", map[string]string{"secret_access_key": "shh"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key_id")
	})
	t.Run("missing secret_access_key", func(t *testing.T) {
		_, err := BuildProvider("route53", map[string]string{"access_key_id": "AKIAEXAMPLE"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_access_key")
	})
}

func TestBuildDigitalOcean(t *testing.T) {
	t.Run("auth_token", func(t *testing.T) {
		_, err := BuildProvider("digitalocean", map[string]string{"auth_token": "do_token"})
		require.NoError(t, err)
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := BuildProvider("digitalocean", map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth_token")
	})
}

func TestBuildRFC2136(t *testing.T) {
	t.Run("all required fields", func(t *testing.T) {
		_, err := BuildProvider("rfc2136", map[string]string{
			"nameserver":     "127.0.0.1:53",
			"tsig_algorithm": "hmac-sha256",
			"tsig_key":       "key.example.com.",
			"tsig_secret":    "AAECAwQFBgcICQoLDA0ODw==",
		})
		require.NoError(t, err)
	})
	t.Run("missing nameserver", func(t *testing.T) {
		_, err := BuildProvider("rfc2136", map[string]string{
			"tsig_algorithm": "hmac-sha256",
			"tsig_key":       "k.",
			"tsig_secret":    "s",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nameserver")
	})
	t.Run("missing tsig fields", func(t *testing.T) {
		_, err := BuildProvider("rfc2136", map[string]string{"nameserver": "127.0.0.1:53"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tsig_algorithm")
	})
}
