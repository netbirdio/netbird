package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTClaims stores information from JWTs
type JWTClaims struct {
	UserId    string
	AccountId string
	Domain    string
}

// extractClaimsFromRequestContext extracts claims from the request context previously filled by the JWT token (after auth)
func extractClaimsFromRequestContext(r *http.Request, authAudiance string) JWTClaims {
	token := r.Context().Value("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	jwtClaims := JWTClaims{}
	jwtClaims.UserId = claims["sub"].(string)
	accountIdClaim, ok := claims[authAudiance+"wt_account_id"]
	if ok {
		jwtClaims.AccountId = accountIdClaim.(string)
	}
	domainClaim, ok := claims[authAudiance+"wt_user_domain"]
	if ok {
		jwtClaims.Domain = domainClaim.(string)
	}
	return jwtClaims
}

//writeJSONObject simply writes object to the HTTP reponse in JSON format
func writeJSONObject(w http.ResponseWriter, obj interface{}) {
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
		return
	}
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
