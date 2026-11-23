package mcpapi

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// ChallengeMiddleware adds the RFC 9728 pointer to the protected resource metadata when a
// call to the MCP endpoint is refused with 401. The API auth middleware writes that 401
// itself, so this has to sit outside it on the root router. Other paths are untouched.
func (b *Broker) ChallengeMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != apiPrefix+Path {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(&challengeWriter{ResponseWriter: w, metadataURL: b.baseURL(r) + apiPrefix + resourceMetadataAPIPath + accountQuery(r)}, r)
		})
	}
}

// challengeWriter sets WWW-Authenticate on a 401 the moment the status is written.
type challengeWriter struct {
	http.ResponseWriter
	metadataURL string
	wroteHeader bool
}

func (c *challengeWriter) WriteHeader(status int) {
	if !c.wroteHeader {
		// Browser-based clients can only read these headers when CORS exposes them.
		c.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version")
		if status == http.StatusUnauthorized {
			c.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, c.metadataURL))
		}
	}
	c.wroteHeader = true
	c.ResponseWriter.WriteHeader(status)
}

func (c *challengeWriter) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// Flush keeps streaming responses working through the wrapper. A flush before any write
// sends the headers, so the implicit 200 goes through WriteHeader first.
func (c *challengeWriter) Flush() {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *challengeWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}
