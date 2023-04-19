package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initRulesTestData(rules ...*server.Rule) *RulesHandler {
	testPolicies := make(map[string]*server.Policy, len(rules))
	for _, rule := range rules {
		policy, err := server.RuleToPolicy(rule)
		if err != nil {
			panic(err)
		}
		testPolicies[policy.ID] = policy
	}
	return &RulesHandler{
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
				}
				return nil
			},
			SaveRuleFunc: func(_, _ string, rule *server.Rule) error {
				if !strings.HasPrefix(rule.ID, "id-") {
					rule.ID = "id-was-set"
				}
				return nil
			},
			GetRuleFunc: func(_, ruleID, _ string) (*server.Rule, error) {
				if ruleID != "idoftherule" {
					return nil, fmt.Errorf("not found")
				}
				return &server.Rule{
					ID:          "idoftherule",
					Name:        "Rule",
					Source:      []string{"idofsrcrule"},
					Destination: []string{"idofdestrule"},
					Flow:        server.TrafficFlowBidirect,
				}, nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				user := server.NewAdminUser("test_user")
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Rules:  map[string]*server.Rule{"id-existed": {ID: "id-existed"}},
					Groups: map[string]*server.Group{
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

func TestRulesGetRule(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "GetRule OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/rules/idoftherule",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetRule not found",
			requestType:    http.MethodGet,
			requestPath:    "/api/rules/notexists",
			expectedStatus: http.StatusNotFound,
		},
	}

	rule := &server.Rule{
		ID:   "idoftherule",
		Name: "Rule",
	}

	p := initRulesTestData(rule)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/rules/{id}", p.GetRule).Methods("GET")
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

			var got api.Rule
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, got.Id, rule.ID)
			assert.Equal(t, got.Name, rule.Name)
		})
	}
}

func TestRulesWriteRule(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedRule   *api.Rule
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:        "WriteRule POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/rules",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Rule","Flow":"bidirect"}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRule: &api.Rule{
				Id:   "id-was-set",
				Name: "Default POSTed Rule",
				Flow: server.TrafficFlowBidirectString,
			},
		},
		{
			name:        "WriteRule POST Invalid Name",
			requestType: http.MethodPost,
			requestPath: "/api/rules",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"","Flow":"bidirect"}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "WriteRule PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Rule","Flow":"bidirect"}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRule: &api.Rule{
				Id:   "id-existed",
				Name: "Default POSTed Rule",
				Flow: server.TrafficFlowBidirectString,
			},
		},
		{
			name:        "WriteRule PUT Invalid Name",
			requestType: http.MethodPut,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"","Flow":"bidirect"}`)),
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	p := initRulesTestData(&server.Rule{
		ID:   "id-existed",
		Name: "Default POSTed Rule",
		Flow: server.TrafficFlowBidirect,
	})

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/rules", p.CreateRule).Methods("POST")
			router.HandleFunc("/api/rules/{id}", p.UpdateRule).Methods("PUT")
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

			got := &api.Rule{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			tc.expectedRule.Id = got.Id

			assert.Equal(t, got, tc.expectedRule)
		})
	}
}
