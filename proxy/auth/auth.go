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

var (
	MethodPassword Method = "password"
	MethodPIN      Method = "pin"
	MethodOIDC     Method = "oidc"
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

// ValidateSessionJWT validates a session JWT and returns the user ID and method.
func ValidateSessionJWT(tokenString, domain string, publicKey ed25519.PublicKey) (userID, method string, err error) {
	if publicKey == nil {
		return "", "", fmt.Errorf("no public key configured for domain")
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithAudience(domain), jwt.WithIssuer(SessionJWTIssuer))
	if err != nil {
		return "", "", fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token claims")
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return "", "", fmt.Errorf("missing subject claim")
	}

	methodClaim, _ := claims["method"].(string)

	return sub, methodClaim, nil
}
