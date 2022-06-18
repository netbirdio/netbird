package testdata

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/handler"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

var audience = "mls"
var apiPath = "/api/users"

func initPeerHandler(t *testing.T) *handler.UserHandler {
	accM, _ := createManagerAPI(t)
	return handler.NewUserHandler(accM, audience)
}

func createManagerAPI(t *testing.T) (*server.DefaultAccountManager, error) {
	store, err := createStoreAPI(t)
	if err != nil {
		return nil, err
	}
	return server.BuildManager(store, server.NewPeersUpdateManager(), nil)
}

func createStoreAPI(t *testing.T) (server.Store, error) {
	dataDir := t.TempDir()
	store, err := server.NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func TestGetGroup2(t *testing.T) {

	p := initPeerHandler(t)

	router := mux.NewRouter()
	router.HandleFunc(apiPath, p.GetUsers).Methods("GET")

	for i := 0; i < 5000; i++ {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, apiPath, nil)
		claimMaps := jwt.MapClaims{}
		claimMaps[jwtclaims.UserIDClaim] = xid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)

		newRequest := req.WithContext(context.WithValue(req.Context(), jwtclaims.TokenUserProperty, token)) //nolint
		// Update the current request with the new context information.
		*req = *newRequest
		router.ServeHTTP(recorder, req)

		res := recorder.Result()
		defer res.Body.Close()

		if status := recorder.Code; status != 200 {
			t.Errorf("handler returned wrong status code: got %v want 200", status)
			return
		}

		content, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("I don't know what I expected; %v", err)
		}
		u := []server.UserInfo{}
		json.Unmarshal(content, &u)
		if len(u) > 1 {
			t.Log(string(content))
		}
	}
}
