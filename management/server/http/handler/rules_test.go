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
			UpdateRuleFunc: func(_ string, ruleID string, operations []server.RuleUpdateOperation) (*server.Rule, error) {
				var rule server.Rule
				rule.ID = ruleID
				for _, operation := range operations {
					switch operation.Type {
					case server.UpdateRuleName:
						rule.Name = operation.Values[0]
					case server.UpdateRuleDescription:
						rule.Description = operation.Values[0]
					case server.UpdateRuleFlow:
						if server.TrafficFlowBidirectString == operation.Values[0] {
							rule.Flow = server.TrafficFlowBidirect
						} else {
							rule.Flow = 100
						}
					case server.UpdateSourceGroups, server.InsertGroupsToSource:
						rule.Source = operation.Values
					case server.UpdateDestinationGroups, server.InsertGroupsToDestination:
						rule.Destination = operation.Values
					case server.RemoveGroupsFromSource, server.RemoveGroupsFromDestination:
					default:
						return nil, fmt.Errorf("no operation")
					}
				}
				return &rule, nil
			},
			GetAccountWithAuthorizationClaimsFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Rules:  map[string]*server.Rule{"id-existed": &server.Rule{ID: "id-existed"}},
					Groups: map[string]*server.Group{
						"F": &server.Group{ID: "F"},
						"G": &server.Group{ID: "G"},
					},
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
		{
			name:        "Write Rule PATCH Name OK",
			requestType: http.MethodPatch,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"name","value":["Default POSTed Rule"]}]`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRule: &api.Rule{
				Id:   "id-existed",
				Name: "Default POSTed Rule",
				Flow: server.TrafficFlowBidirectString,
			},
		},
		{
			name:        "Write Rule PATCH Invalid Name OP",
			requestType: http.MethodPatch,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"insert","path":"name","value":[""]}]`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Write Rule PATCH Invalid Name",
			requestType: http.MethodPatch,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"name","value":[]}]`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Rule PATCH Sources OK",
			requestType: http.MethodPatch,
			requestPath: "/api/rules/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"sources","value":["G","F"]}]`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRule: &api.Rule{
				Id:   "id-existed",
				Flow: server.TrafficFlowBidirectString,
				Sources: []api.GroupMinimum{
					{Id: "G"},
					{Id: "F"}},
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
			router.HandleFunc("/api/rules/{id}", p.PatchRuleHandler).Methods("PATCH")
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

			assert.Equal(t, got, tc.expectedRule)

		})
	}
}
