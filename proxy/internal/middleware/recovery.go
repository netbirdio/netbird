package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

// Recovery middleware recovers from panics and logs the error
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic with stack trace
				log.WithFields(log.Fields{
					"error":       err,
					"method":      r.Method,
					"path":        r.URL.Path,
					"stack":       string(debug.Stack()),
					"remote_addr": r.RemoteAddr,
				}).Error("Panic recovered")

				// Return 500 Internal Server Error
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Internal Server Error")
			}
		}()

		next.ServeHTTP(w, r)
	})
}
