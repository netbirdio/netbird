package middleware

import (
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

type IsUserAdminFunc func(claims jwtclaims.AuthorizationClaims) (bool, error)

// AccessControll middleware to restrict to make POST/PUT/DELETE requests by admin only
type AccessControll struct {
	jwtExtractor jwtclaims.ClaimsExtractor
	isUserAdmin  IsUserAdminFunc
	audience     string
}

// NewAccessControll instance constructor
func NewAccessControll(audience string, isUserAdmin IsUserAdminFunc) *AccessControll {
	return &AccessControll{
		isUserAdmin:  isUserAdmin,
		audience:     audience,
		jwtExtractor: *jwtclaims.NewClaimsExtractor(nil),
	}
}

// Handler method of the middleware which forbinneds all modify requests for non admin users
func (a *AccessControll) Handler(h http.Handler) http.Handler {
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

		h.ServeHTTP(w, r)
	})
}
