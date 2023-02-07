package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initUsers(user ...*server.User) *UserHandler {
	return &UserHandler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				users := make(map[string]*server.User, 0)
				for _, u := range user {
					users[u.Id] = u
				}
				return &server.Account{
					Id:     "12345",
					Domain: "netbird.io",
					Users:  users,
				}, users[claims.UserId], nil
			},
			GetUsersFromAccountFunc: func(accountID, userID string) ([]*server.UserInfo, error) {
				users := make([]*server.UserInfo, 0)
				for _, v := range user {
					users = append(users, &server.UserInfo{
						ID:    v.Id,
						Role:  string(v.Role),
						Name:  "",
						Email: "",
					})
				}
				return users, nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "1",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			}),
		),
	}
}

func TestGetUsers(t *testing.T) {
	users := []*server.User{{Id: "1", Role: "admin"}, {Id: "2", Role: "user"}, {Id: "3", Role: "user"}}
	userHandler := initUsers(users...)

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestBody    io.Reader
		expectedResult []*server.User
	}{
		{name: "GetAllUsers", requestType: http.MethodGet, requestPath: "/api/users/", expectedStatus: http.StatusOK, expectedResult: users},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			rr := httptest.NewRecorder()

			userHandler.GetUsers(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}

			respBody := []*server.UserInfo{}
			err = json.Unmarshal(content, &respBody)
			if err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			if tc.expectedResult != nil {
				for i, resp := range respBody {
					assert.Equal(t, resp.ID, tc.expectedResult[i].Id)
					assert.Equal(t, string(resp.Role), string(tc.expectedResult[i].Role))
				}
			}
		})
	}
}
