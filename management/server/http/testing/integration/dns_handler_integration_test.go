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

func Test_Nameservers_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all nameservers", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/dns/nameservers", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.NameserverGroup{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testNSGroup", got[0].Name)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Nameservers_GetById(t *testing.T) {
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
		nsGroupId      string
		expectedStatus int
		expectGroup    bool
	}{
		{
			name:           "Get existing nameserver group",
			nsGroupId:      "testNSGroupId",
			expectedStatus: http.StatusOK,
			expectGroup:    true,
		},
		{
			name:           "Get non-existing nameserver group",
			nsGroupId:      "nonExistingNSGroupId",
			expectedStatus: http.StatusNotFound,
			expectGroup:    false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/dns/nameservers/{nsgroupId}", "{nsgroupId}", tc.nsGroupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectGroup {
					got := &api.NameserverGroup{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, "testNSGroupId", got.Id)
					assert.Equal(t, "testNSGroup", got.Name)
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

func Test_Nameservers_Create(t *testing.T) {
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
		requestBody    *api.PostApiDnsNameserversJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, nsGroup *api.NameserverGroup)
	}{
		{
			name: "Create nameserver group with single NS",
			requestBody: &api.PostApiDnsNameserversJSONRequestBody{
				Name:        "newNSGroup",
				Description: "a new nameserver group",
				Nameservers: []api.Nameserver{
					{Ip: "8.8.8.8", NsType: "udp", Port: 53},
				},
				Groups:               []string{testing_tools.TestGroupId},
				Primary:              false,
				Domains:              []string{"test.com"},
				Enabled:              true,
				SearchDomainsEnabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, nsGroup *api.NameserverGroup) {
				t.Helper()
				assert.NotEmpty(t, nsGroup.Id)
				assert.Equal(t, "newNSGroup", nsGroup.Name)
				assert.Equal(t, 1, len(nsGroup.Nameservers))
				assert.Equal(t, false, nsGroup.Primary)
			},
		},
		{
			name: "Create primary nameserver group",
			requestBody: &api.PostApiDnsNameserversJSONRequestBody{
				Name:        "primaryNS",
				Description: "primary nameserver",
				Nameservers: []api.Nameserver{
					{Ip: "1.1.1.1", NsType: "udp", Port: 53},
				},
				Groups:  []string{testing_tools.TestGroupId},
				Primary: true,
				Domains: []string{},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, nsGroup *api.NameserverGroup) {
				t.Helper()
				assert.Equal(t, true, nsGroup.Primary)
			},
		},
		{
			name: "Create nameserver group with empty groups",
			requestBody: &api.PostApiDnsNameserversJSONRequestBody{
				Name:        "emptyGroupsNS",
				Description: "no groups",
				Nameservers: []api.Nameserver{
					{Ip: "8.8.8.8", NsType: "udp", Port: 53},
				},
				Groups:  []string{},
				Primary: true,
				Domains: []string{},
				Enabled: true,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/dns/nameservers", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NameserverGroup{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the created NS group directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbNS := testing_tools.VerifyNSGroupInDB(t, db, got.Id)
					assert.Equal(t, got.Name, dbNS.Name)
					assert.Equal(t, got.Primary, dbNS.Primary)
					assert.Equal(t, len(got.Nameservers), len(dbNS.NameServers))
					assert.Equal(t, got.Enabled, dbNS.Enabled)
					assert.Equal(t, got.SearchDomainsEnabled, dbNS.SearchDomainsEnabled)
				}
			})
		}
	}
}

func Test_Nameservers_Update(t *testing.T) {
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
		nsGroupId      string
		requestBody    *api.PutApiDnsNameserversNsgroupIdJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, nsGroup *api.NameserverGroup)
	}{
		{
			name:      "Update nameserver group name",
			nsGroupId: "testNSGroupId",
			requestBody: &api.PutApiDnsNameserversNsgroupIdJSONRequestBody{
				Name:        "updatedNSGroup",
				Description: "updated description",
				Nameservers: []api.Nameserver{
					{Ip: "1.1.1.1", NsType: "udp", Port: 53},
				},
				Groups:               []string{testing_tools.TestGroupId},
				Primary:              false,
				Domains:              []string{"example.com"},
				Enabled:              true,
				SearchDomainsEnabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, nsGroup *api.NameserverGroup) {
				t.Helper()
				assert.Equal(t, "updatedNSGroup", nsGroup.Name)
				assert.Equal(t, "updated description", nsGroup.Description)
			},
		},
		{
			name:      "Update non-existing nameserver group",
			nsGroupId: "nonExistingNSGroupId",
			requestBody: &api.PutApiDnsNameserversNsgroupIdJSONRequestBody{
				Name: "whatever",
				Nameservers: []api.Nameserver{
					{Ip: "1.1.1.1", NsType: "udp", Port: 53},
				},
				Groups:  []string{testing_tools.TestGroupId},
				Primary: true,
				Domains: []string{},
				Enabled: true,
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/dns/nameservers/{nsgroupId}", "{nsgroupId}", tc.nsGroupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NameserverGroup{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the updated NS group directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbNS := testing_tools.VerifyNSGroupInDB(t, db, tc.nsGroupId)
					assert.Equal(t, "updatedNSGroup", dbNS.Name)
					assert.Equal(t, "updated description", dbNS.Description)
					assert.Equal(t, false, dbNS.Primary)
					assert.Equal(t, true, dbNS.Enabled)
					assert.Equal(t, 1, len(dbNS.NameServers))
					assert.Equal(t, false, dbNS.SearchDomainsEnabled)
				}
			})
		}
	}
}

func Test_Nameservers_Delete(t *testing.T) {
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
		nsGroupId      string
		expectedStatus int
	}{
		{
			name:           "Delete existing nameserver group",
			nsGroupId:      "testNSGroupId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing nameserver group",
			nsGroupId:      "nonExistingNSGroupId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/dns/nameservers/{nsgroupId}", "{nsgroupId}", tc.nsGroupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify deletion in DB for successful deletes by privileged users
				if tc.expectedStatus == http.StatusOK && user.expectResponse {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyNSGroupNotInDB(t, db, tc.nsGroupId)
				}
			})
		}
	}
}

func Test_DnsSettings_Get(t *testing.T) {
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
		t.Run(user.name+" - Get DNS settings", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/dns/settings", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := &api.DNSSettings{}
			if err := json.Unmarshal(content, got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.NotNil(t, got.DisabledManagementGroups)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_DnsSettings_Update(t *testing.T) {
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
		name                       string
		requestBody                *api.PutApiDnsSettingsJSONRequestBody
		expectedStatus             int
		verifyResponse             func(t *testing.T, settings *api.DNSSettings)
		expectedDBDisabledMgmtLen  int
		expectedDBDisabledMgmtItem string
	}{
		{
			name: "Update disabled management groups",
			requestBody: &api.PutApiDnsSettingsJSONRequestBody{
				DisabledManagementGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, settings *api.DNSSettings) {
				t.Helper()
				assert.Equal(t, 1, len(settings.DisabledManagementGroups))
				assert.Equal(t, testing_tools.TestGroupId, settings.DisabledManagementGroups[0])
			},
			expectedDBDisabledMgmtLen:  1,
			expectedDBDisabledMgmtItem: testing_tools.TestGroupId,
		},
		{
			name: "Update with empty disabled management groups",
			requestBody: &api.PutApiDnsSettingsJSONRequestBody{
				DisabledManagementGroups: []string{},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, settings *api.DNSSettings) {
				t.Helper()
				assert.Equal(t, 0, len(settings.DisabledManagementGroups))
			},
			expectedDBDisabledMgmtLen: 0,
		},
		{
			name: "Update with non-existing group",
			requestBody: &api.PutApiDnsSettingsJSONRequestBody{
				DisabledManagementGroups: []string{"nonExistingGroupId"},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, "/api/dns/settings", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.DNSSettings{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify DNS settings directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbAccount := testing_tools.VerifyAccountSettings(t, db)
					assert.Equal(t, tc.expectedDBDisabledMgmtLen, len(dbAccount.DNSSettings.DisabledManagementGroups))
					if tc.expectedDBDisabledMgmtItem != "" {
						assert.Contains(t, dbAccount.DNSSettings.DisabledManagementGroups, tc.expectedDBDisabledMgmtItem)
					}
				}
			})
		}
	}
}
