package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// makeJWT builds an unsigned JWT-shaped string (header.payload.signature) with
// the given claims payload. The signature part is arbitrary because
// validateTokenAudience intentionally does not verify it.
func makeJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".unverified-signature"
}

func TestValidateTokenAudience(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		audience string
		wantErr  bool
	}{
		{
			name:     "empty token",
			token:    "",
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "not a JWT - no dots",
			token:    "notajwt",
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "not a JWT - two parts only",
			token:    "header.payload",
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "matching string audience",
			token:    makeJWT(t, map[string]interface{}{"aud": "netbird"}),
			audience: "netbird",
			wantErr:  false,
		},
		{
			name:     "mismatching string audience",
			token:    makeJWT(t, map[string]interface{}{"aud": "other"}),
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "matching audience in array",
			token:    makeJWT(t, map[string]interface{}{"aud": []interface{}{"other", "netbird"}}),
			audience: "netbird",
			wantErr:  false,
		},
		{
			name:     "mismatching audience array",
			token:    makeJWT(t, map[string]interface{}{"aud": []interface{}{"a", "b"}}),
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "missing audience claim",
			token:    makeJWT(t, map[string]interface{}{"sub": "user"}),
			audience: "netbird",
			wantErr:  true,
		},
		{
			name:     "invalid base64 payload",
			token:    "header.!!!not-base64!!!.sig",
			audience: "netbird",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenAudience(tc.token, tc.audience)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

// TestValidateTokenAudienceNoPanic guards the regression where a non-empty
// token without the JWT dot structure caused an index-out-of-range panic.
func TestValidateTokenAudienceNoPanic(t *testing.T) {
	inputs := []string{"a", ".", "a.", "aaaa", "no-dots-here"}
	for _, in := range inputs {
		if err := validateTokenAudience(in, "netbird"); err == nil {
			t.Fatalf("expected error for malformed token %q, got nil", in)
		}
	}
}
