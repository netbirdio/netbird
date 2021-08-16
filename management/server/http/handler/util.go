package handler

import (
	"github.com/golang-jwt/jwt"
	"net/http"
)

// extractAccountIdFromRequestContext extracts accountId from the request context previously filled by the JWT token (after auth)
func extractAccountIdFromRequestContext(r *http.Request) string {
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	//actually a user id but for now we have a 1 to 1 mapping.
	return claims["sub"].(string)
}
