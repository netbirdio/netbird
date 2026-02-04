package proxy

import (
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
)

type AuthCallbackHandler struct {
	proxyService *nbgrpc.ProxyServiceServer
}

func NewAuthCallbackHandler(proxyService *nbgrpc.ProxyServiceServer) *AuthCallbackHandler {
	return &AuthCallbackHandler{
		proxyService: proxyService,
	}
}

func (h *AuthCallbackHandler) RegisterEndpoints(router *mux.Router) {
	router.HandleFunc("/oauth/callback", h.handleCallback).Methods(http.MethodGet)
}

func (h *AuthCallbackHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
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

	// Get OIDC configuration
	oidcConfig := h.proxyService.GetOIDCConfig()

	// Create OIDC provider to discover endpoints
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

	redirectQuery := redirectURL.Query()
	redirectQuery.Set("access_token", token.AccessToken)
	if token.RefreshToken != "" {
		redirectQuery.Set("refresh_token", token.RefreshToken)
	}
	redirectURL.RawQuery = redirectQuery.Encode()

	// Redirect must be HTTPS, regardless of what was originally intended (which should always be HTTPS but better to double-check here).
	redirectURL.Scheme = "https"

	log.WithField("redirect", redirectURL.String()).Debug("OAuth callback: redirecting user with token")
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
