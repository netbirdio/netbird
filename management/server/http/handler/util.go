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

// setCors sets basic cors response headers
func setCors(w http.ResponseWriter) {
	// Todo improve this defaults to filter source domains and required headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
}
