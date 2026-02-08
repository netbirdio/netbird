package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type authenticator interface {
	Authenticate(ctx context.Context, in *proto.AuthenticateRequest, opts ...grpc.CallOption) (*proto.AuthenticateResponse, error)
}

type Scheme interface {
	Type() auth.Method
	// Authenticate should check the passed request and determine whether
	// it represents an authenticated user request. If it does not, then
	// an empty string should indicate an unauthenticated request which
	// will be rejected; optionally, it can also return any data that should
	// be included in a UI template when prompting the user to authenticate.
	// If the request is authenticated, then a session token should be returned.
	Authenticate(*http.Request) (token string, promptData string)
}

type DomainConfig struct {
	Schemes           []Scheme
	SessionPublicKey  ed25519.PublicKey
	SessionExpiration time.Duration
}

type Middleware struct {
	domainsMux sync.RWMutex
	domains    map[string]DomainConfig
	logger     *log.Logger
}

func NewMiddleware(logger *log.Logger) *Middleware {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Middleware{
		domains: make(map[string]DomainConfig),
		logger:  logger,
	}
}

// Protect applies authentication middleware to the passed handler.
// For each incoming request it will be checked against the middleware's
// internal list of protected domains.
// If the Host domain in the inbound request is not present, then it will
// simply be passed through.
// However, if the Host domain is present, then the specified authentication
// schemes for that domain will be applied to the request.
// In the event that no authentication schemes are defined for the domain,
// then the request will also be simply passed through.
func (mw *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		mw.domainsMux.RLock()
		config, exists := mw.domains[host]
		mw.domainsMux.RUnlock()

		mw.logger.Debugf("checking authentication for host: %s, exists: %t", host, exists)

		// Domains that are not configured here or have no authentication schemes applied should simply pass through.
		if !exists || len(config.Schemes) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Check for an existing session cookie (contains JWT)
		if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
			if userID, method, err := auth.ValidateSessionJWT(cookie.Value, host, config.SessionPublicKey); err == nil {
				ctx := withAuthMethod(r.Context(), auth.Method(method))
				ctx = withAuthUser(ctx, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Try to authenticate with each scheme.
		methods := make(map[string]string)
		for _, scheme := range config.Schemes {
			token, promptData := scheme.Authenticate(r)
			if token != "" {
				if _, _, err := auth.ValidateSessionJWT(token, host, config.SessionPublicKey); err != nil {
					if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
						cd.SetOrigin(proxy.OriginAuth)
					}
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				expiration := config.SessionExpiration
				if expiration == 0 {
					expiration = auth.DefaultSessionExpiry
				}
				http.SetCookie(w, &http.Cookie{
					Name:     auth.SessionCookieName,
					Value:    token,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   int(expiration.Seconds()),
				})

				// Redirect instead of forwarding the auth POST to the backend.
				// The browser will follow with a GET carrying the new session cookie.
				if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
					cd.SetOrigin(proxy.OriginAuth)
				}
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
				return
			}
			methods[scheme.Type().String()] = promptData
		}

		if cd := proxy.CapturedDataFromContext(r.Context()); cd != nil {
			cd.SetOrigin(proxy.OriginAuth)
		}
		web.ServeHTTP(w, r, map[string]any{"methods": methods}, http.StatusUnauthorized)
	})
}

// AddDomain registers authentication schemes for the given domain.
// If schemes are provided, a valid session public key is required to sign/verify
// session JWTs. Returns an error if the key is missing or invalid.
// Callers must not serve the domain if this returns an error, to avoid
// exposing an unauthenticated service.
func (mw *Middleware) AddDomain(domain string, schemes []Scheme, publicKeyB64 string, expiration time.Duration) error {
	if len(schemes) == 0 {
		mw.domainsMux.Lock()
		defer mw.domainsMux.Unlock()
		mw.domains[domain] = DomainConfig{}
		return nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("decode session public key for domain %s: %w", domain, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid session public key size for domain %s: got %d, want %d", domain, len(pubKeyBytes), ed25519.PublicKeySize)
	}

	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	mw.domains[domain] = DomainConfig{
		Schemes:           schemes,
		SessionPublicKey:  pubKeyBytes,
		SessionExpiration: expiration,
	}
	return nil
}

func (mw *Middleware) RemoveDomain(domain string) {
	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	delete(mw.domains, domain)
}
