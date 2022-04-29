package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initGroupTestData(groups ...*server.Group) *Groups {
	return &Groups{
		accountManager: &mock_server.MockAccountManager{
			SaveGroupFunc: func(accountID string, group *server.Group) error {
				return nil
			},
			GetGroupFunc: func(_, groupID string) (*server.Group, error) {
				if groupID != "idofthegroup" {
					return nil, fmt.Errorf("not found")
				}
				return &server.Group{
					ID:   "idofthegroup",
					Name: "Group",
				}, nil
			},
			GetAccountWithAuthorizationClaimsFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
				}, nil
			},
		},
		authAudience: "",
		jwtExtractor: jwtclaims.ClaimsExtractor{
			ExtractClaimsFromRequestContext: func(r *http.Request, authAudiance string) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			},
		},
	}
}

func TestGetGroup(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "GetGroup OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/idofthegroup",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetGroup not found",
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/notexists",
			expectedStatus: http.StatusNotFound,
		},
	}

	group := &server.Group{
		ID:   "idofthegroup",
		Name: "Group",
	}

	p := initGroupTestData(group)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/groups/{id}", p.GetGroupHandler).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
				return
			}

			if !tc.expectedBody {
				return
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			got := &server.Group{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, got.ID, group.ID)
			assert.Equal(t, got.Name, group.Name)
		})
	}
}
