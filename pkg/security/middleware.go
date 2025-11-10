package security

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// SecurityHeadersMiddleware adds security-related HTTP headers to responses
type SecurityHeadersMiddleware struct {
	// Enable or disable various security headers
	EnableHSTS           bool
	HSTSMaxAge          int           // In seconds
	HSTSIncludeSubs     bool
	HSTSPreload         bool
	EnableCSP           bool
	CSP                 string        // Content Security Policy
	EnableXSSProtection bool          // Enable X-XSS-Protection header
	EnableFrameOptions  bool          // Enable X-Frame-Options header
	FrameOptions        string        // DENY, SAMEORIGIN, or ALLOW-FROM uri
	EnableCTO           bool          // Enable X-Content-Type-Options header
	EnableReferrer      bool          // Enable Referrer-Policy header
	ReferrerPolicy      string        // no-referrer, no-referrer-when-downgrade, origin, etc.
	EnablePermissions   bool          // Enable Permissions-Policy header
	PermissionsPolicy   string        // Permissions-Policy value
	EnableCORS          bool          // Enable CORS headers
	AllowedOrigins      []string      // Allowed origins for CORS
	AllowedMethods      []string      // Allowed HTTP methods for CORS
	AllowedHeaders      []string      // Allowed headers for CORS
	AllowCredentials    bool          // Allow credentials in CORS
	ExposeHeaders       []string      // Headers to expose in CORS
	MaxAge              time.Duration // Max age for CORS preflight

	// Logger
	logger *logrus.Logger
}

// NewSecurityHeadersMiddleware creates a new SecurityHeadersMiddleware with default settings
func NewSecurityHeadersMiddleware() *SecurityHeadersMiddleware {
	return &SecurityHeadersMiddleware{
		EnableHSTS:           true,
		HSTSMaxAge:           63072000, // 2 years in seconds
		HSTSIncludeSubs:      true,
		HSTSPreload:          false,
		EnableCSP:            true,
		CSP:                  "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
		EnableXSSProtection:  true,
		EnableFrameOptions:   true,
		FrameOptions:         "SAMEORIGIN",
		EnableCTO:            true,
		EnableReferrer:       true,
		ReferrerPolicy:       "strict-origin-when-cross-origin",
		EnablePermissions:    true,
		PermissionsPolicy:    "geolocation=(), microphone=(), camera=()",
		EnableCORS:           true,
		AllowedOrigins:       []string{"*"},
		AllowedMethods:       []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:       []string{"Content-Type", "Authorization"},
		AllowCredentials:     true,
		ExposeHeaders:        []string{},
		MaxAge:               300 * time.Second, // 5 minutes
		logger:               logrus.StandardLogger(),
	}
}

// Middleware returns an HTTP middleware function that adds security headers
func (s *SecurityHeadersMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS preflight requests
		if r.Method == http.MethodOptions && s.EnableCORS {
			s.handlePreflight(w, r)
			return
		}

		// Create a response wrapper to capture the status code
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Don't add security headers to error responses
		if rw.status >= 400 {
			return
		}

		// Add security headers
		s.addSecurityHeaders(rw, r)
	})
}

// handlePreflight handles CORS preflight requests
func (s *SecurityHeadersMiddleware) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// Check if the origin is allowed
	if !s.isOriginAllowed(origin) {
		s.logger.WithField("origin", origin).Debug("Origin not allowed for CORS")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Set CORS headers
	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", origin)
	headers.Set("Access-Control-Allow-Methods", strings.Join(s.AllowedMethods, ", "))
	headers.Set("Access-Control-Allow-Headers", strings.Join(s.AllowedHeaders, ", "))

	if s.AllowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}

	if len(s.ExposeHeaders) > 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(s.ExposeHeaders, ", "))
	}

	// Set preflight cache duration
	headers.Set("Access-Control-Max-Age", strconv.Itoa(int(s.MaxAge.Seconds())))

	// End the request
	w.WriteHeader(http.StatusNoContent)
}

// addSecurityHeaders adds security headers to the response
func (s *SecurityHeadersMiddleware) addSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()

	// HSTS (HTTP Strict Transport Security)
	if s.EnableHSTS && r.TLS != nil {
		hstsValue := "max-age=" + strconv.Itoa(s.HSTSMaxAge)
		if s.HSTSIncludeSubs {
			hstsValue += "; includeSubDomains"
		}
		if s.HSTSPreload {
			hstsValue += "; preload"
		}
		headers.Set("Strict-Transport-Security", hstsValue)
	}

	// Content Security Policy
	if s.EnableCSP && s.CSP != "" {
		headers.Set("Content-Security-Policy", s.CSP)
	}

	// X-XSS-Protection
	if s.EnableXSSProtection {
		headers.Set("X-XSS-Protection", "1; mode=block")
	}

	// X-Frame-Options
	if s.EnableFrameOptions && s.FrameOptions != "" {
		headers.Set("X-Frame-Options", s.FrameOptions)
	}

	// X-Content-Type-Options
	if s.EnableCTO {
		headers.Set("X-Content-Type-Options", "nosniff")
	}

	// Referrer-Policy
	if s.EnableReferrer && s.ReferrerPolicy != "" {
		headers.Set("Referrer-Policy", s.ReferrerPolicy)
	}

	// Permissions-Policy
	if s.EnablePermissions && s.PermissionsPolicy != "" {
		headers.Set("Permissions-Policy", s.PermissionsPolicy)
	}

	// CORS headers
	if s.EnableCORS {
		origin := r.Header.Get("Origin")
		if s.isOriginAllowed(origin) {
			headers.Set("Access-Control-Allow-Origin", origin)
			if s.AllowCredentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}
		}

		if len(s.ExposeHeaders) > 0 {
			headers.Set("Access-Control-Expose-Headers", strings.Join(s.ExposeHeaders, ", "))
		}
	}

	// Remove Server header
	headers.Del("Server")

	// Add X-Powered-By header with a fake value to avoid fingerprinting
	headers.Set("X-Powered-By", "Go")
}

// isOriginAllowed checks if the origin is allowed for CORS
func (s *SecurityHeadersMiddleware) isOriginAllowed(origin string) bool {
	if len(s.AllowedOrigins) == 0 {
		return false
	}

	// Allow all origins
	if len(s.AllowedOrigins) == 1 && s.AllowedOrigins[0] == "*" {
		return true
	}

	// Check if the origin is in the allowed list
	for _, allowed := range s.AllowedOrigins {
		if origin == allowed || allowed == "*" {
			return true
		}

		// Support for wildcard subdomains (e.g., *.example.com)
		if strings.HasPrefix(allowed, "*.") {
			// Remove the wildcard prefix
			domain := allowed[2:]
			// Check if the origin ends with the domain
			if strings.HasSuffix(origin, domain) {
				// Make sure it's not a partial match (e.g., example.com vs evil-example.com)
				if len(origin) > len(domain) && origin[len(origin)-len(domain)-1] == '.' {
					return true
				}
			}
		}
	}

	return false
}

// responseWriter is a wrapper around http.ResponseWriter that captures the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before writing the header
func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// BasicAuthMiddleware provides HTTP Basic Authentication
func BasicAuthMiddleware(username, password, realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()

			if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
				subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				http.Error(w, "Unauthorized.", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecureHeaders is a convenience function that adds common security headers
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()

		// Security Headers
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("X-XSS-Protection", "1; mode=block")
		headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Remove Server header
		headers.Del("Server")

		// Add X-Powered-By header with a fake value
		headers.Set("X-Powered-By", "Go")

		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}
