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

func Test_Zones_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all zones", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/dns/zones", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Zone{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "Test Zone", got[0].Name)
			assert.Equal(t, "example.com", got[0].Domain)
			assert.Equal(t, true, got[0].Enabled)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Zones_GetById(t *testing.T) {
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
		zoneId         string
		expectedStatus int
		expectZone     bool
	}{
		{
			name:           "Get existing zone",
			zoneId:         "testZoneId",
			expectedStatus: http.StatusOK,
			expectZone:     true,
		},
		{
			name:           "Get non-existing zone",
			zoneId:         "nonExistingZoneId",
			expectedStatus: http.StatusNotFound,
			expectZone:     false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/dns/zones/{zoneId}", "{zoneId}", tc.zoneId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectZone {
					got := &api.Zone{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, "testZoneId", got.Id)
					assert.Equal(t, "Test Zone", got.Name)
					assert.Equal(t, "example.com", got.Domain)
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

func Test_Zones_Create(t *testing.T) {
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

	enabled := true
	disabled := false

	tt := []struct {
		name           string
		requestBody    *api.PostApiDnsZonesJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, zone *api.Zone)
	}{
		{
			name: "Create zone with valid data",
			requestBody: &api.PostApiDnsZonesJSONRequestBody{
				Name:               "New Zone",
				Domain:             "newzone.com",
				Enabled:            &enabled,
				EnableSearchDomain: false,
				DistributionGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, zone *api.Zone) {
				t.Helper()
				assert.NotEmpty(t, zone.Id)
				assert.Equal(t, "New Zone", zone.Name)
				assert.Equal(t, "newzone.com", zone.Domain)
				assert.Equal(t, true, zone.Enabled)
				assert.Equal(t, false, zone.EnableSearchDomain)
				assert.Equal(t, 1, len(zone.DistributionGroups))
			},
		},
		{
			name: "Create zone with search domain enabled",
			requestBody: &api.PostApiDnsZonesJSONRequestBody{
				Name:               "Search Zone",
				Domain:             "search.example.com",
				Enabled:            &enabled,
				EnableSearchDomain: true,
				DistributionGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, zone *api.Zone) {
				t.Helper()
				assert.NotEmpty(t, zone.Id)
				assert.Equal(t, "Search Zone", zone.Name)
				assert.Equal(t, true, zone.EnableSearchDomain)
			},
		},
		{
			name: "Create disabled zone",
			requestBody: &api.PostApiDnsZonesJSONRequestBody{
				Name:               "Disabled Zone",
				Domain:             "disabled.example.com",
				Enabled:            &disabled,
				EnableSearchDomain: false,
				DistributionGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, zone *api.Zone) {
				t.Helper()
				assert.NotEmpty(t, zone.Id)
				assert.Equal(t, false, zone.Enabled)
			},
		},
		{
			name: "Create zone with empty distribution groups",
			requestBody: &api.PostApiDnsZonesJSONRequestBody{
				Name:               "No Groups Zone",
				Domain:             "nogroups.com",
				Enabled:            &enabled,
				EnableSearchDomain: false,
				DistributionGroups: []string{},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/dns/zones", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Zone{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the created zone directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbZone := testing_tools.VerifyZoneInDB(t, db, got.Id)
					assert.Equal(t, got.Name, dbZone.Name)
					assert.Equal(t, got.Domain, dbZone.Domain)
					assert.Equal(t, got.Enabled, dbZone.Enabled)
					assert.Equal(t, got.EnableSearchDomain, dbZone.EnableSearchDomain)
				}
			})
		}
	}
}

func Test_Zones_Update(t *testing.T) {
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

	enabled := true

	tt := []struct {
		name           string
		zoneId         string
		requestBody    *api.PutApiDnsZonesZoneIdJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, zone *api.Zone)
	}{
		{
			name:   "Update zone name and domain",
			zoneId: "testZoneId",
			requestBody: &api.PutApiDnsZonesZoneIdJSONRequestBody{
				Name:               "Updated Zone",
				Domain:             "updated.example.com",
				Enabled:            &enabled,
				EnableSearchDomain: true,
				DistributionGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, zone *api.Zone) {
				t.Helper()
				assert.Equal(t, "Updated Zone", zone.Name)
				assert.Equal(t, "updated.example.com", zone.Domain)
				assert.Equal(t, true, zone.EnableSearchDomain)
			},
		},
		{
			name:   "Update non-existing zone",
			zoneId: "nonExistingZoneId",
			requestBody: &api.PutApiDnsZonesZoneIdJSONRequestBody{
				Name:               "Whatever",
				Domain:             "whatever.com",
				Enabled:            &enabled,
				EnableSearchDomain: false,
				DistributionGroups: []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/dns/zones/{zoneId}", "{zoneId}", tc.zoneId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Zone{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the updated zone directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbZone := testing_tools.VerifyZoneInDB(t, db, tc.zoneId)
					assert.Equal(t, "Updated Zone", dbZone.Name)
					assert.Equal(t, "updated.example.com", dbZone.Domain)
					assert.Equal(t, true, dbZone.Enabled)
					assert.Equal(t, true, dbZone.EnableSearchDomain)
				}
			})
		}
	}
}

func Test_Zones_Delete(t *testing.T) {
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
		zoneId         string
		expectedStatus int
	}{
		{
			name:           "Delete existing zone",
			zoneId:         "testZoneId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing zone",
			zoneId:         "nonExistingZoneId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/dns/zones/{zoneId}", "{zoneId}", tc.zoneId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify deletion in DB for successful deletes by privileged users
				if tc.expectedStatus == http.StatusOK && user.expectResponse {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyZoneNotInDB(t, db, tc.zoneId)
				}
			})
		}
	}
}
