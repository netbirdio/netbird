package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/http/api"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

func initRulesTestData(rules ...*server.Rule) *Rules {
	return &Rules{
		accountManager: &mock_server.MockAccountManager{
			SaveRuleFunc: func(_ string, rule *server.Rule) error {
				if !strings.HasPrefix(rule.ID, "id-") {
					rule.ID = "id-was-set"
				}
				return nil
			},
			GetRuleFunc: func(_, ruleID string) (*server.Rule, error) {
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
			GetAccountWithAuthorizationClaimsFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Rules:  map[string]*server.Rule{"id-existed": &server.Rule{}},
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
			router.HandleFunc("/api/rules/{id}", p.GetRuleHandler).Methods("GET")
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

			assert.Equal(t, got.ID, rule.ID)
			assert.Equal(t, got.Name, rule.Name)
		})
	}
}

func TestRulesSaveRule(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedRule   *server.Rule
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:        "SaveRule POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/rules",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Rule","Flow":"bidirect"}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRule: &server.Rule{
				ID:   "id-was-set",
				Name: "Default POSTed Rule",
				Flow: server.TrafficFlowBidirect,
			},
		},
		{
			name:        "SaveRule PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Rule","Flow":"bidirect"}`)),
			expectedStatus: http.StatusOK,
			expectedRule: &server.Rule{
				ID:   "id-existed",
				Name: "Default POSTed Rule",
				Flow: server.TrafficFlowBidirect,
			},
		},
	}

	p := initRulesTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/rules", p.CreateRuleHandler).Methods("POST")
			router.HandleFunc("/api/rules/{id}", p.UpdateRuleHandler).Methods("PUT")
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

			if tc.requestType != http.MethodPost {
				assert.Equal(t, got.ID, tc.expectedRule.ID)
			}
			assert.Equal(t, got.Name, tc.expectedRule.Name)
			assert.Equal(t, got.Flow, "bidirect")
		})
	}
}
