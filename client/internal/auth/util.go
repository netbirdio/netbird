package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

// validateTokenAudience checks that the token is a well-formed JWT whose
// audience claim matches the expected audience.
//
// It does NOT verify the token's cryptographic signature and therefore must not
// be treated as an authenticity check. The token is obtained by the client
// directly from the IdP token endpoint over TLS, and its signature is verified
// server-side by the management server against the IdP's JWKS
// (see shared/auth/jwt/validator.go). This function is only a client-side
// sanity check that the returned token targets the expected audience.
func validateTokenAudience(token string, audience string) error {
	if token == "" {
		return fmt.Errorf("token received is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token is not a well-formed JWT")
	}

	claimsString, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	claims := Claims{}
	err = json.Unmarshal(claimsString, &claims)
	if err != nil {
		return err
	}

	if claims.Audience == nil {
		return fmt.Errorf("required token field audience is absent")
	}

	// Audience claim of JWT can be a string or an array of strings
	switch aud := claims.Audience.(type) {
	case string:
		if aud == audience {
			return nil
		}
	case []interface{}:
		for _, audItem := range aud {
			if audStr, ok := audItem.(string); ok && audStr == audience {
				return nil
			}
		}
	}

	return fmt.Errorf("invalid JWT token audience field")
}
