package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
)

const (
	existingAccountID = "existingAccountID"
	notFoundAccountID = "notFoundAccountID"
	existingUserID    = "existingUserID"
	notFoundUserID    = "notFoundUserID"
	existingTokenID   = "existingTokenID"
	notFoundTokenID   = "notFoundTokenID"
	domain            = "hotmail.com"
)

var testAccount = &server.Account{
	Id:     existingAccountID,
	Domain: domain,
	Users: map[string]*server.User{
		existingUserID: {
			Id: existingUserID,
			PATs: map[string]*server.PersonalAccessToken{
				existingTokenID: {
					ID:             existingTokenID,
					Name:           "My first token",
					HashedToken:    "someHash",
					ExpirationDate: time.Now().UTC().AddDate(0, 0, 7),
					CreatedBy:      existingUserID,
					CreatedAt:      time.Now().UTC(),
					LastUsed:       time.Now().UTC(),
				},
				"token2": {
					ID:             "token2",
					Name:           "My second token",
					HashedToken:    "someOtherHash",
					ExpirationDate: time.Now().UTC().AddDate(0, 0, 7),
					CreatedBy:      existingUserID,
					CreatedAt:      time.Now().UTC(),
					LastUsed:       time.Now().UTC(),
				},
			},
		},
	},
}

func initPATTestData() *PATHandler {
	return &PATHandler{
		accountManager: &mock_server.MockAccountManager{
			CreatePATFunc: func(accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*server.PersonalAccessTokenGenerated, error) {
				if accountID != existingAccountID {
					return nil, status.Errorf(status.NotFound, "account with ID %s not found", accountID)
				}
				if targetUserID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s not found", targetUserID)
				}
				return &server.PersonalAccessTokenGenerated{
					PlainToken:          "nbp_z1pvsg2wP3EzmEou4S679KyTNhov632eyrXe",
					PersonalAccessToken: server.PersonalAccessToken{},
				}, nil
			},

			GetAccountFromTokenFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return testAccount, testAccount.Users[existingUserID], nil
			},
			DeletePATFunc: func(accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
				if accountID != existingAccountID {
					return status.Errorf(status.NotFound, "account with ID %s not found", accountID)
				}
				if targetUserID != existingUserID {
					return status.Errorf(status.NotFound, "user with ID %s not found", targetUserID)
				}
				if tokenID != existingTokenID {
					return status.Errorf(status.NotFound, "token with ID %s not found", tokenID)
				}
				return nil
			},
			GetPATFunc: func(accountID string, initiatorUserID string, targetUserID string, tokenID string) (*server.PersonalAccessToken, error) {
				if accountID != existingAccountID {
					return nil, status.Errorf(status.NotFound, "account with ID %s not found", accountID)
				}
				if targetUserID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s not found", targetUserID)
				}
				if tokenID != existingTokenID {
					return nil, status.Errorf(status.NotFound, "token with ID %s not found", tokenID)
				}
				return testAccount.Users[existingUserID].PATs[existingTokenID], nil
			},
			GetAllPATsFunc: func(accountID string, initiatorUserID string, targetUserID string) ([]*server.PersonalAccessToken, error) {
				if accountID != existingAccountID {
					return nil, status.Errorf(status.NotFound, "account with ID %s not found", accountID)
				}
				if targetUserID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s not found", targetUserID)
				}
				return []*server.PersonalAccessToken{testAccount.Users[existingUserID].PATs[existingTokenID], testAccount.Users[existingUserID].PATs["token2"]}, nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    existingUserID,
					Domain:    domain,
					AccountId: testNSGroupAccountID,
				}
			}),
		),
	}
}

func TestTokenHandlers(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "Get All Tokens",
			requestType:    http.MethodGet,
			requestPath:    "/api/users/" + existingUserID + "/tokens",
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
		{
			name:           "Get Existing Token",
			requestType:    http.MethodGet,
			requestPath:    "/api/users/" + existingUserID + "/tokens/" + existingTokenID,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
		{
			name:           "Get Not Existing Token",
			requestType:    http.MethodGet,
			requestPath:    "/api/users/" + existingUserID + "/tokens/" + notFoundTokenID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Delete Existing Token",
			requestType:    http.MethodDelete,
			requestPath:    "/api/users/" + existingUserID + "/tokens/" + existingTokenID,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete Not Existing Token",
			requestType:    http.MethodDelete,
			requestPath:    "/api/users/" + existingUserID + "/tokens/" + notFoundTokenID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/users/" + existingUserID + "/tokens",
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"expires_in\":7}")),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
	}

	p := initPATTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/users/{userId}/tokens", p.GetAllTokens).Methods("GET")
			router.HandleFunc("/api/users/{userId}/tokens/{tokenId}", p.GetToken).Methods("GET")
			router.HandleFunc("/api/users/{userId}/tokens", p.CreateToken).Methods("POST")
			router.HandleFunc("/api/users/{userId}/tokens/{tokenId}", p.DeleteToken).Methods("DELETE")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			if !tc.expectedBody {
				return
			}

			switch tc.name {
			case "POST OK":
				got := &api.PersonalAccessTokenGenerated{}
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
				assert.NotEmpty(t, got.PlainToken)
				assert.Equal(t, server.PATLength, len(got.PlainToken))
			case "Get All Tokens":
				expectedTokens := []api.PersonalAccessToken{
					toTokenResponse(*testAccount.Users[existingUserID].PATs[existingTokenID]),
					toTokenResponse(*testAccount.Users[existingUserID].PATs["token2"]),
				}

				var got []api.PersonalAccessToken
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
				assert.True(t, cmp.Equal(got, expectedTokens))
			case "Get Existing Token":
				expectedToken := toTokenResponse(*testAccount.Users[existingUserID].PATs[existingTokenID])
				got := &api.PersonalAccessToken{}
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				assert.True(t, cmp.Equal(*got, expectedToken))
			}

		})
	}
}

func toTokenResponse(serverToken server.PersonalAccessToken) api.PersonalAccessToken {
	return api.PersonalAccessToken{
		Id:             serverToken.ID,
		Name:           serverToken.Name,
		CreatedAt:      serverToken.CreatedAt,
		LastUsed:       &serverToken.LastUsed,
		CreatedBy:      serverToken.CreatedBy,
		ExpirationDate: serverToken.ExpirationDate,
	}
}
