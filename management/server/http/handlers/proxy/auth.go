package proxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/auth"
)

// AuthCallbackHandler handles OAuth callbacks for proxy authentication.
type AuthCallbackHandler struct {
	proxyService   *nbgrpc.ProxyServiceServer
	rateLimiter    *middleware.APIRateLimiter
	trustedProxies []netip.Prefix
}

// NewAuthCallbackHandler creates a new OAuth callback handler.
func NewAuthCallbackHandler(proxyService *nbgrpc.ProxyServiceServer, trustedProxies []netip.Prefix) *AuthCallbackHandler {
	rateLimiterConfig := &middleware.RateLimiterConfig{
		RequestsPerMinute: 10,
		Burst:             15,
		CleanupInterval:   5 * time.Minute,
		LimiterTTL:        10 * time.Minute,
	}

	return &AuthCallbackHandler{
		proxyService:   proxyService,
		rateLimiter:    middleware.NewAPIRateLimiter(rateLimiterConfig),
		trustedProxies: trustedProxies,
	}
}

// RegisterEndpoints registers the OAuth callback endpoint.
func (h *AuthCallbackHandler) RegisterEndpoints(router *mux.Router) {
	router.HandleFunc(types.ProxyCallbackEndpoint, h.handleCallback).Methods(http.MethodGet)
}

func (h *AuthCallbackHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	clientIP := h.resolveClientIP(r)
	if !h.rateLimiter.Allow(clientIP) {
		log.WithField("client_ip", clientIP).Warn("OAuth callback rate limit exceeded")
		http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
		return
	}

	state := r.URL.Query().Get("state")

	codeVerifier, originalURL, err := h.proxyService.ValidateState(state)
	if err != nil {
		log.WithError(err).Error("OAuth callback state validation failed")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	redirectURL, err := url.Parse(originalURL)
	if err != nil {
		log.WithError(err).Error("Failed to parse redirect URL")
		http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
		return
	}

	oidcConfig := h.proxyService.GetOIDCConfig()

	provider, err := oidc.NewProvider(r.Context(), oidcConfig.Issuer)
	if err != nil {
		log.WithError(err).Error("Failed to create OIDC provider")
		http.Error(w, "Failed to create OIDC provider", http.StatusInternalServerError)
		return
	}

	token, err := (&oauth2.Config{
		ClientID:    oidcConfig.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: oidcConfig.CallbackURL,
	}).Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(codeVerifier))
	if err != nil {
		log.WithError(err).Error("Failed to exchange code for token")
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	userID := extractUserIDFromToken(r.Context(), provider, oidcConfig, token)
	if userID == "" {
		log.Error("Failed to extract user ID from OIDC token")
		http.Error(w, "Failed to validate token", http.StatusUnauthorized)
		return
	}

	// Group validation is performed by the proxy via ValidateSession gRPC call.
	// This allows the proxy to show 403 pages directly without redirect dance.

	sessionToken, err := h.proxyService.GenerateSessionToken(r.Context(), redirectURL.Hostname(), userID, auth.MethodOIDC)
	if err != nil {
		log.WithError(err).Error("Failed to create session token")
		redirectURL.Scheme = "https"
		query := redirectURL.Query()
		query.Set("error", "access_denied")
		query.Set("error_description", "Service configuration error")
		redirectURL.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}

	redirectURL.Scheme = "https"

	query := redirectURL.Query()
	query.Set("session_token", sessionToken)
	redirectURL.RawQuery = query.Encode()

	log.WithField("redirect", redirectURL.Host).Debug("OAuth callback: redirecting user with session token")
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func extractUserIDFromToken(ctx context.Context, provider *oidc.Provider, config nbgrpc.ProxyOIDCConfig, token *oauth2.Token) string {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Warn("No id_token in OIDC response")
		return ""
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.WithError(err).Warn("Failed to verify ID token")
		return ""
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.WithError(err).Warn("Failed to extract claims from ID token")
		return ""
	}

	return claims.Subject
}

// resolveClientIP extracts the real client IP from the request.
// When trustedProxies is non-empty and the direct peer is trusted,
// it walks X-Forwarded-For right-to-left skipping trusted IPs.
// Otherwise it returns RemoteAddr directly.
func (h *AuthCallbackHandler) resolveClientIP(r *http.Request) string {
	remoteIP := extractHost(r.RemoteAddr)

	if len(h.trustedProxies) == 0 || !isTrustedProxy(remoteIP, h.trustedProxies) {
		return remoteIP
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		if !isTrustedProxy(ip, h.trustedProxies) {
			return ip
		}
	}

	// All IPs in XFF are trusted; return the leftmost as best guess.
	if first := strings.TrimSpace(parts[0]); first != "" {
		return first
	}
	return remoteIP
}

func extractHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func isTrustedProxy(ipStr string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
