package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"net/http"
	"time"
)

// writeJSONObject simply writes object to the HTTP reponse in JSON format
func writeJSONObject(w http.ResponseWriter, obj interface{}) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err := json.NewEncoder(w).Encode(obj)
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
		return
	}
}

// Duration is used strictly for JSON requests/responses due to duration marshalling issues
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

func getJWTAccount(accountManager server.AccountManager,
	jwtExtractor jwtclaims.ClaimsExtractor,
	authAudience string, r *http.Request) (*server.Account, error) {

	jwtClaims := jwtExtractor.ExtractClaimsFromRequestContext(r, authAudience)

	account, err := accountManager.GetAccountFromToken(jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account, nil
}
