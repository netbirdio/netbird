package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	nbContext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/util"
)

// RequestMiddleware middleware enrich context with requestID and accountID
type RequestMiddleware struct {
	claimsExtract jwtclaims.ClaimsExtractor
}

// NewRequestMiddleware instance constructor
func NewRequestMiddleware(claimsExtract *jwtclaims.ClaimsExtractor) *RequestMiddleware {
	return &RequestMiddleware{
		claimsExtract: *claimsExtract,
	}
}

// Handler method of the middleware which enriches context with requestID and accountID
func (a *RequestMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint
		ctx := context.WithValue(r.Context(), nbContext.LogSourceKey, util.HTTPSource)

		reqID := uuid.New().String()
		//nolint
		ctx = context.WithValue(ctx, nbContext.RequestIDKey, reqID)

		claims := a.claimsExtract.FromRequestContext(r)
		//nolint
		ctx = context.WithValue(ctx, nbContext.InitiatorIDKey, claims.UserId)
		//nolint
		ctx = context.WithValue(ctx, nbContext.AccountIDKey, claims.AccountId)

		h.ServeHTTP(w, r.WithContext(ctx))
	})
}
