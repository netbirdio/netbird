package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLine_ValidPeerConnection(t *testing.T) {
	line := `netbird_peer_connection,deployment_type=cloud,connection_type=ice,attempt_type=initial,version=1.0.0,os=linux,arch=amd64,peer_id=abcdef0123456789,connection_pair_id=pair1234 signaling_to_connection_seconds=1.5,connection_to_wg_handshake_seconds=0.5,total_seconds=2 1234567890`
	assert.NoError(t, validateLine(line))
}

func TestValidateLine_ValidSync(t *testing.T) {
	line := `netbird_sync,deployment_type=selfhosted,version=2.0.0,os=darwin,arch=arm64,peer_id=abcdef0123456789 duration_seconds=1.5 1234567890`
	assert.NoError(t, validateLine(line))
}

func TestValidateLine_ValidLogin(t *testing.T) {
	line := `netbird_login,deployment_type=cloud,result=success,version=1.0.0,os=linux,arch=amd64,peer_id=abcdef0123456789 duration_seconds=3.2 1234567890`
	assert.NoError(t, validateLine(line))
}

func TestValidateLine_UnknownMeasurement(t *testing.T) {
	line := `unknown_metric,foo=bar value=1 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown measurement")
}

func TestValidateLine_UnknownTag(t *testing.T) {
	line := `netbird_sync,deployment_type=cloud,evil_tag=injected,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=1.5 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown tag")
}

func TestValidateLine_UnknownField(t *testing.T) {
	line := `netbird_sync,deployment_type=cloud,version=1.0.0,os=linux,arch=amd64,peer_id=abc injected_field=1 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestValidateLine_NegativeValue(t *testing.T) {
	line := `netbird_sync,deployment_type=cloud,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=-1.5 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestValidateLine_DurationTooLarge(t *testing.T) {
	line := `netbird_sync,deployment_type=cloud,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=999 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestValidateLine_TotalSecondsTooLarge(t *testing.T) {
	line := `netbird_peer_connection,deployment_type=cloud,connection_type=ice,attempt_type=initial,version=1.0.0,os=linux,arch=amd64,peer_id=abc,connection_pair_id=pair total_seconds=500 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestValidateLine_TagValueTooLong(t *testing.T) {
	longTag := strings.Repeat("a", maxTagValueLength+1)
	line := `netbird_sync,deployment_type=` + longTag + `,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=1.5 1234567890`
	err := validateLine(line)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag value too long")
}

func TestValidateLineProtocol_MultipleLines(t *testing.T) {
	body := []byte(
		"netbird_sync,deployment_type=cloud,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=1.5 1234567890\n" +
			"netbird_login,deployment_type=cloud,result=success,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=2.0 1234567890\n",
	)
	validated, err := validateLineProtocol(body)
	require.NoError(t, err)
	assert.Contains(t, string(validated), "netbird_sync")
	assert.Contains(t, string(validated), "netbird_login")
}

func TestValidateLineProtocol_RejectsOnBadLine(t *testing.T) {
	body := []byte(
		"netbird_sync,deployment_type=cloud,version=1.0.0,os=linux,arch=amd64,peer_id=abc duration_seconds=1.5 1234567890\n" +
			"evil_metric,foo=bar value=1 1234567890\n",
	)
	_, err := validateLineProtocol(body)
	require.Error(t, err)
}

func TestValidateAuth(t *testing.T) {
	tests := []struct {
		name    string
		peerID  string
		wantErr bool
	}{
		{"valid hex", "abcdef0123456789", false},
		{"empty", "", true},
		{"too short", "abcdef01234567", true},
		{"too long", "abcdef01234567890", true},
		{"invalid hex", "ghijklmnopqrstuv", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			if tt.peerID != "" {
				r.Header.Set("X-Peer-ID", tt.peerID)
			}
			err := validateAuth(r)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
