package middleware

import (
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/ratelimit"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func BuildMiddleware(rateLimiter *ratelimit.APIRateLimiter, authManager auth.Manager, accountManager account.Manager, metrics telemetry.AppMetrics, isValidChildAcctFunc IsValidChildAccountFunc) []mux.MiddlewareFunc {
	toret := make([]mux.MiddlewareFunc, 0)

	toret = append(toret, metrics.HTTPMiddleware().Handler)
	toret = append(toret, cors.AllowAll().Handler)

	if rateLimiter == nil {
		log.Warn("NewAPIHandler: nil rate limiter, rate limiting disabled")
		rateLimiter = ratelimit.NewAPIRateLimiter(nil)
		rateLimiter.SetEnabled(false)
	}
	toret = append(toret, NewAuthMiddleware(
		authManager,
		accountManager.GetAccountIDFromUserAuth,
		accountManager.SyncUserJWTGroups,
		accountManager.GetUserFromUserAuth,
		rateLimiter,
		metrics.GetMeter(),
		isValidChildAcctFunc,
	).Handler)

	return toret
}
