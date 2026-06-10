// Package auth contains exported proxy auth values.
// These are used to ensure coherent usage across management and proxy implementations.
package auth

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Method string

const (
	MethodPassword Method = "password"
	MethodPIN      Method = "pin"
	MethodOIDC     Method = "oidc"
	MethodHeader   Method = "header"
)

func (m Method) String() string {
	return string(m)
}

const (
	SessionCookieName    = "nb_session"
	DefaultSessionExpiry = 24 * time.Hour
	SessionJWTIssuer     = "netbird-management"
)

// ResolveProto determines the protocol scheme based on the forwarded proto
// configuration. When set to "http" or "https" the value is used directly.
// Otherwise TLS state is used: if conn is non-nil "https" is returned, else "http".
func ResolveProto(forwardedProto string, conn *tls.ConnectionState) string {
	switch forwardedProto {
	case "http", "https":
		return forwardedProto
	default:
		if conn != nil {
			return "https"
		}
		return "http"
	}
}

// ValidateSessionJWT validates a session JWT and returns the user ID, the
// user's email (when carried), the authentication method, any embedded
// group memberships, and the parallel group display names. email,
// groups, and groupNames may be empty for tokens minted before those
// claims were introduced. groupNames pairs positionally with groups.
func ValidateSessionJWT(tokenString, domain string, publicKey ed25519.PublicKey) (userID, email, method string, groups, groupNames []string, err error) {
	if publicKey == nil {
		return "", "", "", nil, nil, fmt.Errorf("no public key configured for domain")
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithAudience(domain), jwt.WithIssuer(SessionJWTIssuer))
	if err != nil {
		return "", "", "", nil, nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", "", nil, nil, fmt.Errorf("invalid token claims")
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return "", "", "", nil, nil, fmt.Errorf("missing subject claim")
	}

	methodClaim, _ := claims["method"].(string)
	emailClaim, _ := claims["email"].(string)
	groups = extractGroupsClaim(claims["groups"])
	groupNames = extractGroupsClaim(claims["group_names"])

	return sub, emailClaim, methodClaim, groups, groupNames, nil
}

// extractGroupsClaim decodes the "groups" claim into a string slice. The JWT
// library decodes JSON arrays as []interface{}, so we coerce element-wise
// and skip non-string entries silently.
func extractGroupsClaim(claim interface{}) []string {
	raw, ok := claim.([]interface{})
	if !ok {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	groups := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			groups = append(groups, s)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}
