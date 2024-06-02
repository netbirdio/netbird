package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initPoliciesTestData(policies ...*server.Policy) *Policies {
	testPolicies := make(map[string]*server.Policy, len(policies))
	for _, policy := range policies {
		testPolicies[policy.ID] = policy
	}
	return &Policies{
		accountManager: &mock_server.MockAccountManager{
			GetPolicyFunc: func(_, policyID, _ string) (*server.Policy, error) {
				policy, ok := testPolicies[policyID]
				if !ok {
					return nil, status.Errorf(status.NotFound, "policy not found")
				}
				return policy, nil
			},
			SavePolicyFunc: func(_, _ string, policy *server.Policy) error {
				if !strings.HasPrefix(policy.ID, "id-") {
					policy.ID = "id-was-set"
					policy.Rules[0].ID = "id-was-set"
				}
				return nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				user := server.NewAdminUser("test_user")
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Policies: []*server.Policy{
						{ID: "id-existed"},
					},
					Groups: map[string]*nbgroup.Group{
						"F": {ID: "F"},
						"G": {ID: "G"},
					},
					Users: map[string]*server.User{
						"test_user": user,
					},
				}, user, nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			}),
		),
	}
}

func TestPoliciesGetPolicy(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "GetPolicy OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/policies/idofthepolicy",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetPolicy not found",
			requestType:    http.MethodGet,
			requestPath:    "/api/policies/notexists",
			expectedStatus: http.StatusNotFound,
		},
	}

	policy := &server.Policy{
		ID:   "idofthepolicy",
		Name: "Rule",
		Rules: []*server.PolicyRule{
			{ID: "idoftherule", Name: "Rule"},
		},
	}

	p := initPoliciesTestData(policy)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/policies/{policyId}", p.GetPolicy).Methods("GET")
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

			var got api.Policy
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, *got.Id, policy.ID)
			assert.Equal(t, got.Name, policy.Name)
		})
	}
}

func TestPoliciesWritePolicy(t *testing.T) {
	str := func(s string) *string { return &s }
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedPolicy *api.Policy
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:        "WritePolicy POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/policies",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                    "Name":"Default POSTed Policy",
                    "Rules":[
                        {
                            "Name":"Default POSTed Policy",
                            "Description": "Description",
                            "Protocol": "tcp",
                            "Action": "accept",
                            "Bidirectional":true
                        }
                ]}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPolicy: &api.Policy{
				Id:   str("id-was-set"),
				Name: "Default POSTed Policy",
				Rules: []api.PolicyRule{
					{
						Id:            str("id-was-set"),
						Name:          "Default POSTed Policy",
						Description:   str("Description"),
						Protocol:      "tcp",
						Action:        "accept",
						Bidirectional: true,
					},
				},
			},
		},
		{
			name:        "WritePolicy POST Invalid Name",
			requestType: http.MethodPost,
			requestPath: "/api/policies",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":""}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "WritePolicy PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/policies/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                    "ID": "id-existed",
                    "Name":"Default POSTed Policy",
                    "Rules":[
                        {
                            "ID": "id-existed",
                            "Name":"Default POSTed Policy",
                            "Description": "Description",
                            "Protocol": "tcp",
                            "Action": "accept",
                            "Bidirectional":true
                        }
                ]}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPolicy: &api.Policy{
				Id:   str("id-existed"),
				Name: "Default POSTed Policy",
				Rules: []api.PolicyRule{
					{
						Id:            str("id-existed"),
						Name:          "Default POSTed Policy",
						Description:   str("Description"),
						Protocol:      "tcp",
						Action:        "accept",
						Bidirectional: true,
					},
				},
			},
		},
		{
			name:        "WritePolicy PUT Invalid Name",
			requestType: http.MethodPut,
			requestPath: "/api/policies/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"ID":"id-existed","Name":"","Rules":[{"ID":"id-existed"}]}`)),
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	p := initPoliciesTestData(&server.Policy{
		ID:   "id-existed",
		Name: "Default POSTed Rule",
		Rules: []*server.PolicyRule{
			{
				ID:            "id-existed",
				Name:          "Default POSTed Rule",
				Bidirectional: true,
			},
		},
	})

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/policies", p.CreatePolicy).Methods("POST")
			router.HandleFunc("/api/policies/{policyId}", p.UpdatePolicy).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
				return
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			if !tc.expectedBody {
				return
			}

			expected, err := json.Marshal(tc.expectedPolicy)
			if err != nil {
				t.Fatalf("marshal expected policy: %v", err)
				return
			}

			assert.Equal(t, strings.Trim(string(content), " \n"), string(expected), "content mismatch")
		})
	}
}
