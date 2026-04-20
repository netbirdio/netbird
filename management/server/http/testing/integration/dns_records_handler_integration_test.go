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

func Test_Records_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all records", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/dns/zones/testZoneId/records", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.DNSRecord{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "sub.example.com", got[0].Name)
			assert.Equal(t, api.DNSRecordTypeA, got[0].Type)
			assert.Equal(t, "1.2.3.4", got[0].Content)
			assert.Equal(t, 300, got[0].Ttl)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Records_GetById(t *testing.T) {
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
		recordId       string
		expectedStatus int
		expectRecord   bool
	}{
		{
			name:           "Get existing record",
			zoneId:         "testZoneId",
			recordId:       "testRecordId",
			expectedStatus: http.StatusOK,
			expectRecord:   true,
		},
		{
			name:           "Get non-existing record",
			zoneId:         "testZoneId",
			recordId:       "nonExistingRecordId",
			expectedStatus: http.StatusNotFound,
			expectRecord:   false,
		},
		{
			name:           "Get record from non-existing zone",
			zoneId:         "nonExistingZoneId",
			recordId:       "testRecordId",
			expectedStatus: http.StatusNotFound,
			expectRecord:   false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, true)

				path := strings.Replace("/api/dns/zones/{zoneId}/records/{recordId}", "{zoneId}", tc.zoneId, 1)
				path = strings.Replace(path, "{recordId}", tc.recordId, 1)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectRecord {
					got := &api.DNSRecord{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, "testRecordId", got.Id)
					assert.Equal(t, "sub.example.com", got.Name)
					assert.Equal(t, api.DNSRecordTypeA, got.Type)
					assert.Equal(t, "1.2.3.4", got.Content)
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

func Test_Records_Create(t *testing.T) {
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
		requestBody    *api.PostApiDnsZonesZoneIdRecordsJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, record *api.DNSRecord)
	}{
		{
			name:   "Create A record",
			zoneId: "testZoneId",
			requestBody: &api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
				Name:    "new.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "5.6.7.8",
				Ttl:     600,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, record *api.DNSRecord) {
				t.Helper()
				assert.NotEmpty(t, record.Id)
				assert.Equal(t, "new.example.com", record.Name)
				assert.Equal(t, api.DNSRecordTypeA, record.Type)
				assert.Equal(t, "5.6.7.8", record.Content)
				assert.Equal(t, 600, record.Ttl)
			},
		},
		{
			name:   "Create CNAME record",
			zoneId: "testZoneId",
			requestBody: &api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
				Name:    "alias.example.com",
				Type:    api.DNSRecordTypeCNAME,
				Content: "target.example.com",
				Ttl:     300,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, record *api.DNSRecord) {
				t.Helper()
				assert.NotEmpty(t, record.Id)
				assert.Equal(t, "alias.example.com", record.Name)
				assert.Equal(t, api.DNSRecordTypeCNAME, record.Type)
				assert.Equal(t, "target.example.com", record.Content)
			},
		},
		{
			name:   "Create record with invalid content for A type",
			zoneId: "testZoneId",
			requestBody: &api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
				Name:    "bad.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "not-an-ip",
				Ttl:     300,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:   "Create record in non-existing zone",
			zoneId: "nonExistingZoneId",
			requestBody: &api.PostApiDnsZonesZoneIdRecordsJSONRequestBody{
				Name:    "new.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "5.6.7.8",
				Ttl:     600,
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

				path := strings.Replace("/api/dns/zones/{zoneId}/records", "{zoneId}", tc.zoneId, 1)
				req := testing_tools.BuildRequest(t, body, http.MethodPost, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.DNSRecord{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the created record directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbRecord := testing_tools.VerifyRecordInDB(t, db, got.Id)
					assert.Equal(t, got.Name, dbRecord.Name)
					assert.Equal(t, got.Content, dbRecord.Content)
					assert.Equal(t, got.Ttl, dbRecord.TTL)
				}
			})
		}
	}
}

func Test_Records_Update(t *testing.T) {
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
		recordId       string
		requestBody    *api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody
		expectedStatus int
		verifyResponse func(t *testing.T, record *api.DNSRecord)
	}{
		{
			name:     "Update record content and TTL",
			zoneId:   "testZoneId",
			recordId: "testRecordId",
			requestBody: &api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody{
				Name:    "sub.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "10.20.30.40",
				Ttl:     600,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, record *api.DNSRecord) {
				t.Helper()
				assert.Equal(t, "sub.example.com", record.Name)
				assert.Equal(t, "10.20.30.40", record.Content)
				assert.Equal(t, 600, record.Ttl)
			},
		},
		{
			name:     "Update non-existing record",
			zoneId:   "testZoneId",
			recordId: "nonExistingRecordId",
			requestBody: &api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody{
				Name:    "sub.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "10.20.30.40",
				Ttl:     600,
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:     "Update record in non-existing zone",
			zoneId:   "nonExistingZoneId",
			recordId: "testRecordId",
			requestBody: &api.PutApiDnsZonesZoneIdRecordsRecordIdJSONRequestBody{
				Name:    "sub.example.com",
				Type:    api.DNSRecordTypeA,
				Content: "10.20.30.40",
				Ttl:     600,
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

				path := strings.Replace("/api/dns/zones/{zoneId}/records/{recordId}", "{zoneId}", tc.zoneId, 1)
				path = strings.Replace(path, "{recordId}", tc.recordId, 1)
				req := testing_tools.BuildRequest(t, body, http.MethodPut, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.DNSRecord{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify the updated record directly in the DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbRecord := testing_tools.VerifyRecordInDB(t, db, tc.recordId)
					assert.Equal(t, "10.20.30.40", dbRecord.Content)
					assert.Equal(t, 600, dbRecord.TTL)
				}
			})
		}
	}
}

func Test_Records_Delete(t *testing.T) {
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
		recordId       string
		expectedStatus int
	}{
		{
			name:           "Delete existing record",
			zoneId:         "testZoneId",
			recordId:       "testRecordId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing record",
			zoneId:         "testZoneId",
			recordId:       "nonExistingRecordId",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Delete record from non-existing zone",
			zoneId:         "nonExistingZoneId",
			recordId:       "testRecordId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/dns_zones.sql", nil, false)

				path := strings.Replace("/api/dns/zones/{zoneId}/records/{recordId}", "{zoneId}", tc.zoneId, 1)
				path = strings.Replace(path, "{recordId}", tc.recordId, 1)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify deletion in DB for successful deletes by privileged users
				if tc.expectedStatus == http.StatusOK && user.expectResponse {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyRecordNotInDB(t, db, tc.recordId)
				}
			})
		}
	}
}
