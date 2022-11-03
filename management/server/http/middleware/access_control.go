package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

const (
	IsUserAdminProperty = "isAdminUser"
)

type IsUserAdminFunc func(claims jwtclaims.AuthorizationClaims) (bool, error)

// AccessControl middleware to restrict to make POST/PUT/DELETE requests by admin only
type AccessControl struct {
	jwtExtractor jwtclaims.ClaimsExtractor
	isUserAdmin  IsUserAdminFunc
	audience     string
}

// NewAccessControl instance constructor
func NewAccessControl(audience string, isUserAdmin IsUserAdminFunc) *AccessControl {
	return &AccessControl{
		isUserAdmin:  isUserAdmin,
		audience:     audience,
		jwtExtractor: *jwtclaims.NewClaimsExtractor(nil),
	}
}

// Handler method of the middleware which forbids all modify requests for non admin users
// It also adds
func (a *AccessControl) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtClaims := a.jwtExtractor.ExtractClaimsFromRequestContext(r, a.audience)

		ok, err := a.isUserAdmin(jwtClaims)
		if err != nil {
			http.Error(w, fmt.Sprintf("error get user from JWT: %v", err), http.StatusUnauthorized)
			return
		}

		if !ok {
			switch r.Method {
			case http.MethodDelete, http.MethodPost, http.MethodPatch, http.MethodPut:
				http.Error(w, "user is not admin", http.StatusForbidden)
				return
			}
		}

		newRequest := r.Clone(context.WithValue(r.Context(), IsUserAdminProperty, ok)) //nolint
		// Update the current request with the new context information.
		*r = *newRequest

		h.ServeHTTP(w, r)
	})
}
