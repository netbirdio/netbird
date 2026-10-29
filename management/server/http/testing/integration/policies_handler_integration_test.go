//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Policies_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all policies", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/policies.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/policies", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Policy{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testPolicy", got[0].Name)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Policies_GetById(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		policyId       string
		expectedStatus int
		expectPolicy   bool
	}{
		{
			name:           "Get existing policy",
			policyId:       "testPolicyId",
			expectedStatus: http.StatusOK,
			expectPolicy:   true,
		},
		{
			name:           "Get non-existing policy",
			policyId:       "nonExistingPolicyId",
			expectedStatus: http.StatusNotFound,
			expectPolicy:   false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/policies.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/policies/{policyId}", "{policyId}", tc.policyId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectPolicy {
					got := &api.Policy{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.NotNil(t, got.Id)
					assert.Equal(t, tc.policyId, *got.Id)
					assert.Equal(t, "testPolicy", got.Name)
					assert.Equal(t, true, got.Enabled)
					assert.GreaterOrEqual(t, len(got.Rules), 1)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_Policies_Create(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	srcGroups := []string{testing_tools.TestGroupId}
	dstGroups := []string{testing_tools.TestGroupId}

	tt := []struct {
		name           string
		requestBody    *api.PolicyCreate
		expectedStatus int
		verifyResponse func(t *testing.T, policy *api.Policy)
	}{
		{
			name: "Create policy with accept rule",
			requestBody: &api.PolicyCreate{
				Name:    "newPolicy",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:          "allowAll",
						Enabled:       true,
						Action:        "accept",
						Protocol:      "all",
						Bidirectional: true,
						Sources:       &srcGroups,
						Destinations:  &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, policy *api.Policy) {
				t.Helper()
				assert.NotNil(t, policy.Id)
				assert.Equal(t, "newPolicy", policy.Name)
				assert.Equal(t, true, policy.Enabled)
				assert.Equal(t, 1, len(policy.Rules))
				assert.Equal(t, "allowAll", policy.Rules[0].Name)
			},
		},
		{
			name: "Create policy with drop rule",
			requestBody: &api.PolicyCreate{
				Name:    "dropPolicy",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:          "dropAll",
						Enabled:       true,
						Action:        "drop",
						Protocol:      "all",
						Bidirectional: true,
						Sources:       &srcGroups,
						Destinations:  &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, policy *api.Policy) {
				t.Helper()
				assert.Equal(t, "dropPolicy", policy.Name)
			},
		},
		{
			name: "Create policy with TCP rule and ports",
			requestBody: &api.PolicyCreate{
				Name:    "tcpPolicy",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:          "tcpRule",
						Enabled:       true,
						Action:        "accept",
						Protocol:      "tcp",
						Bidirectional: true,
						Sources:       &srcGroups,
						Destinations:  &dstGroups,
						Ports:         &[]string{"80", "443"},
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, policy *api.Policy) {
				t.Helper()
				assert.Equal(t, "tcpPolicy", policy.Name)
				assert.NotNil(t, policy.Rules[0].Ports)
				assert.Equal(t, 2, len(*policy.Rules[0].Ports))
			},
		},
		{
			name: "Create policy with empty name",
			requestBody: &api.PolicyCreate{
				Name:    "",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:         "rule",
						Enabled:      true,
						Action:       "accept",
						Protocol:     "all",
						Sources:      &srcGroups,
						Destinations: &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "Create policy with no rules",
			requestBody: &api.PolicyCreate{
				Name:    "noRulesPolicy",
				Enabled: true,
				Rules:   []api.PolicyRuleUpdate{},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/policies.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/policies", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Policy{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify policy exists in DB with correct fields
					db := testing_tools.GetDB(t, am.GetStore())
					dbPolicy := testing_tools.VerifyPolicyInDB(t, db, *got.Id)
					assert.Equal(t, tc.requestBody.Name, dbPolicy.Name)
					assert.Equal(t, tc.requestBody.Enabled, dbPolicy.Enabled)
					assert.Equal(t, len(tc.requestBody.Rules), len(dbPolicy.Rules))
				}
			})
		}
	}
}

func Test_Policies_Update(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	srcGroups := []string{testing_tools.TestGroupId}
	dstGroups := []string{testing_tools.TestGroupId}

	tt := []struct {
		name           string
		policyId       string
		requestBody    *api.PolicyCreate
		expectedStatus int
		verifyResponse func(t *testing.T, policy *api.Policy)
	}{
		{
			name:     "Update policy name",
			policyId: "testPolicyId",
			requestBody: &api.PolicyCreate{
				Name:    "updatedPolicy",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:          "testRule",
						Enabled:       true,
						Action:        "accept",
						Protocol:      "all",
						Bidirectional: true,
						Sources:       &srcGroups,
						Destinations:  &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, policy *api.Policy) {
				t.Helper()
				assert.Equal(t, "updatedPolicy", policy.Name)
			},
		},
		{
			name:     "Update policy enabled state",
			policyId: "testPolicyId",
			requestBody: &api.PolicyCreate{
				Name:    "testPolicy",
				Enabled: false,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:          "testRule",
						Enabled:       true,
						Action:        "accept",
						Protocol:      "all",
						Bidirectional: true,
						Sources:       &srcGroups,
						Destinations:  &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, policy *api.Policy) {
				t.Helper()
				assert.Equal(t, false, policy.Enabled)
			},
		},
		{
			name:     "Update non-existing policy",
			policyId: "nonExistingPolicyId",
			requestBody: &api.PolicyCreate{
				Name:    "whatever",
				Enabled: true,
				Rules: []api.PolicyRuleUpdate{
					{
						Name:         "rule",
						Enabled:      true,
						Action:       "accept",
						Protocol:     "all",
						Sources:      &srcGroups,
						Destinations: &dstGroups,
					},
				},
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/policies.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/policies/{policyId}", "{policyId}", tc.policyId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Policy{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify updated policy in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbPolicy := testing_tools.VerifyPolicyInDB(t, db, tc.policyId)
					assert.Equal(t, tc.requestBody.Name, dbPolicy.Name)
					assert.Equal(t, tc.requestBody.Enabled, dbPolicy.Enabled)
				}
			})
		}
	}
}

func Test_Policies_Delete(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		policyId       string
		expectedStatus int
	}{
		{
			name:           "Delete existing policy",
			policyId:       "testPolicyId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing policy",
			policyId:       "nonExistingPolicyId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/policies.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/policies/{policyId}", "{policyId}", tc.policyId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if expectResponse && tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyPolicyNotInDB(t, db, tc.policyId)
				}
			})
		}
	}
}
