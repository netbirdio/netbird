package middleware

import (
	"net/http"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// GetUser function defines a function to fetch user from Account by jwtclaims.AuthorizationClaims
type GetUser func(claims jwtclaims.AuthorizationClaims) (*server.User, error)

// AccessControl middleware to restrict to make POST/PUT/DELETE requests by admin only
type AccessControl struct {
	claimsExtract jwtclaims.ClaimsExtractor
	getUser       GetUser
}

// NewAccessControl instance constructor
func NewAccessControl(audience, userIDClaim string, getUser GetUser) *AccessControl {
	return &AccessControl{
		claimsExtract: *jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(audience),
			jwtclaims.WithUserIDClaim(userIDClaim),
		),
		getUser: getUser,
	}
}

var tokenPathRegexp = regexp.MustCompile(`^.*/api/users/.*/tokens.*$`)

// Handler method of the middleware which forbids all modify requests for non admin users
func (a *AccessControl) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if bypass.ShouldBypass(r.URL.Path, h, w, r) {
			return
		}

		claims := a.claimsExtract.FromRequestContext(r)

		user, err := a.getUser(claims)
		if err != nil {
			log.Errorf("failed to get user from claims: %s", err)
			util.WriteError(status.Errorf(status.Unauthorized, "invalid JWT"), w)
			return
		}

		if user.IsBlocked() {
			util.WriteError(status.Errorf(status.PermissionDenied, "the user has no access to the API or is blocked"), w)
			return
		}

		if !user.HasAdminPower() {
			switch r.Method {
			case http.MethodDelete, http.MethodPost, http.MethodPatch, http.MethodPut:

				if tokenPathRegexp.MatchString(r.URL.Path) {
					log.Debugf("valid Path")
					h.ServeHTTP(w, r)
					return
				}

				util.WriteError(status.Errorf(status.PermissionDenied, "only users with admin power can perform this operation"), w)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}
