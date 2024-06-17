package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

func TestRequestMiddleware_Handler(t *testing.T) {

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// used to validate if the context is enriched with values
		if r.Context().Value(context.RequestIDKey) == nil || r.Context().Value(context.RequestIDKey) == "" {
			t.Errorf("requestID not set in context")
		}
		if r.Context().Value(context.RequestIDKey) == nil || r.Context().Value(context.RequestIDKey) == "" {
			t.Errorf("requestID not set in context")
		}
		if r.Context().Value(context.InitiatorIDKey) == nil || r.Context().Value(context.InitiatorIDKey) == "" {
			t.Errorf("initiatorID not set in context")
		}
		if r.Context().Value(context.AccountIDKey) == nil || r.Context().Value(context.AccountIDKey) == "" {
			t.Errorf("accountID not set in context")
		}
	})

	requestMiddleware := NewRequestMiddleware(
		jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    userID,
					Domain:    domain,
					AccountId: accountID,
				}
			}),
		),
	)

	handlerToTest := requestMiddleware.Handler(nextHandler)

	req := httptest.NewRequest("GET", "http://testing/test", nil)

	rec := httptest.NewRecorder()

	handlerToTest.ServeHTTP(rec, req)
}
