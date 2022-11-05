package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	authAudience string, r *http.Request) (*server.Account, *server.User, error) {

	claims := jwtExtractor.ExtractClaimsFromRequestContext(r, authAudience)

	account, err := accountManager.GetAccountFromToken(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting account of a user %s: %v", claims.UserId, err)
	}

	user := account.Users[claims.UserId]
	if user == nil {
		// this is not really possible because we got an account by user ID
		return nil, nil, fmt.Errorf("user %s not found", claims.UserId)
	}

	return account, user, nil
}

func toHTTPError(err error, w http.ResponseWriter) {
	errStatus, ok := status.FromError(err)
	if ok && errStatus.Code() == codes.Internal {
		http.Error(w, errStatus.String(), http.StatusInternalServerError)
		return
	}

	if ok && errStatus.Code() == codes.NotFound {
		http.Error(w, errStatus.String(), http.StatusNotFound)
		return
	}

	if ok && errStatus.Code() == codes.InvalidArgument {
		http.Error(w, errStatus.String(), http.StatusBadRequest)
		return
	}

	unhandledMSG := fmt.Sprintf("got unhandled error code, error: %s", errStatus.String())
	log.Error(unhandledMSG)
	http.Error(w, unhandledMSG, http.StatusInternalServerError)
}
