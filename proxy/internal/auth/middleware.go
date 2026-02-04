package auth

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/management/proto"
)

//go:embed auth.gohtml
var authTemplate string

type Method string

var (
	MethodPassword Method = "password"
	MethodPIN      Method = "pin"
	MethodOIDC     Method = "oidc"
	MethodLink     Method = "link"
)

func (m Method) String() string {
	return string(m)
}

const (
	sessionCookieName = "nb_session"
	sessionExpiration = 24 * time.Hour
)

type session struct {
	UserID    string
	Method    Method
	CreatedAt time.Time
}

type authenticator interface {
	Authenticate(ctx context.Context, in *proto.AuthenticateRequest, opts ...grpc.CallOption) (*proto.AuthenticateResponse, error)
}

type Scheme interface {
	Type() Method
	// Authenticate should check the passed request and determine whether
	// it represents an authenticated user request. If it does not, then
	// an empty string should indicate an unauthenticated request which
	// will be rejected; optionally, it can also return any data that should
	// be included in a UI template when prompting the user to authenticate.
	// If the request is authenticated, then a user id should be returned.
	Authenticate(*http.Request) (userid string, promptData string)
}

type Middleware struct {
	domainsMux  sync.RWMutex
	domains     map[string][]Scheme
	sessionsMux sync.RWMutex
	sessions    map[string]*session
}

func NewMiddleware() *Middleware {
	mw := &Middleware{
		domains:  make(map[string][]Scheme),
		sessions: make(map[string]*session),
	}
	// TODO: goroutine is leaked here.
	go mw.cleanupSessions()
	return mw
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
	tmpl := template.Must(template.New("auth").Parse(authTemplate))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		mw.domainsMux.RLock()
		schemes, exists := mw.domains[host]
		mw.domainsMux.RUnlock()

		// Domains that are not configured here or have no authentication schemes applied should simply pass through.
		if !exists || len(schemes) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Check for an existing session to avoid users having to authenticate for every request.
		// TODO: This does not work if you are load balancing across multiple proxy servers.
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			mw.sessionsMux.RLock()
			sess, ok := mw.sessions[cookie.Value]
			mw.sessionsMux.RUnlock()
			if ok {
				ctx := withAuthMethod(r.Context(), sess.Method)
				ctx = withAuthUser(ctx, sess.UserID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Try to authenticate with each scheme.
		methods := make(map[string]string)
		for _, s := range schemes {
			userid, promptData := s.Authenticate(r)
			if userid != "" {
				mw.createSession(w, r, userid, s.Type())
				// Clean the path and redirect to the naked URL.
				// This is intended to prevent leaking potentially
				// sensitive query parameters for authentication
				// methods.
				http.Redirect(w, r, r.URL.Path, http.StatusFound)
				return
			}
			methods[s.Type().String()] = promptData
		}

		if err := tmpl.Execute(w, struct {
			Methods map[string]string
		}{
			Methods: methods,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
}

func (mw *Middleware) AddDomain(domain string, schemes []Scheme) {
	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	mw.domains[domain] = schemes
}

func (mw *Middleware) RemoveDomain(domain string) {
	mw.domainsMux.Lock()
	defer mw.domainsMux.Unlock()
	delete(mw.domains, domain)
}

func (mw *Middleware) createSession(w http.ResponseWriter, r *http.Request, userID string, method Method) {
	// Generate a random sessionID
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sessionID := base64.URLEncoding.EncodeToString(b)

	mw.sessionsMux.Lock()
	mw.sessions[sessionID] = &session{
		UserID:    userID,
		Method:    method,
		CreatedAt: time.Now(),
	}
	mw.sessionsMux.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		HttpOnly: true,                 // This cookie is only for proxy access, so no scripts should touch it.
		Secure:   true,                 // The proxy only accepts TLS traffic regardless of the service proxied behind.
		SameSite: http.SameSiteLaxMode, // TODO: might this actually be strict mode?
	})
}

func (mw *Middleware) cleanupSessions() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-sessionExpiration)
		mw.sessionsMux.Lock()
		for id, sess := range mw.sessions {
			if sess.CreatedAt.Before(cutoff) {
				delete(mw.sessions, id)
			}
		}
		mw.sessionsMux.Unlock()
	}
}
