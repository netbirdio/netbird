package handler

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt"
	"net/http"
	"time"
)

// extractAccountIdFromRequestContext extracts accountId from the request context previously filled by the JWT token (after auth)
func extractAccountIdFromRequestContext(r *http.Request) string {
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	//actually a user id but for now we have a 1 to 1 mapping.
	return claims["sub"].(string)
}

//Duration is used strictly for JSON requests/responses due to duration marshalling issues
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}
