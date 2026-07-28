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
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Routes_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all routes", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/routes", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Route{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 2, len(got))

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Routes_GetById(t *testing.T) {
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
		routeId        string
		expectedStatus int
		expectRoute    bool
	}{
		{
			name:           "Get existing route",
			routeId:        "testRouteId",
			expectedStatus: http.StatusOK,
			expectRoute:    true,
		},
		{
			name:           "Get non-existing route",
			routeId:        "nonExistingRouteId",
			expectedStatus: http.StatusNotFound,
			expectRoute:    false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/routes/{routeId}", "{routeId}", tc.routeId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectRoute {
					got := &api.Route{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, tc.routeId, got.Id)
					assert.Equal(t, "Test Network Route", got.Description)
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

func Test_Routes_Create(t *testing.T) {
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

	networkCIDR := "10.10.0.0/24"
	peerID := testing_tools.TestPeerId
	peerGroups := []string{"peerGroupId"}

	tt := []struct {
		name           string
		requestBody    *api.RouteRequest
		expectedStatus int
		verifyResponse func(t *testing.T, route *api.Route)
	}{
		{
			name: "Create network route with peer",
			requestBody: &api.RouteRequest{
				Description: "New network route",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "newNet",
				Metric:      100,
				Masquerade:  true,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, route *api.Route) {
				t.Helper()
				assert.NotEmpty(t, route.Id)
				assert.Equal(t, "New network route", route.Description)
				assert.Equal(t, 100, route.Metric)
				assert.Equal(t, true, route.Masquerade)
				assert.Equal(t, true, route.Enabled)
			},
		},
		{
			name: "Create network route with peer groups",
			requestBody: &api.RouteRequest{
				Description: "Route with peer groups",
				Network:     &networkCIDR,
				PeerGroups:  &peerGroups,
				NetworkId:   "peerGroupNet",
				Metric:      150,
				Masquerade:  false,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, route *api.Route) {
				t.Helper()
				assert.NotEmpty(t, route.Id)
				assert.Equal(t, "Route with peer groups", route.Description)
			},
		},
		{
			name: "Create route with empty network_id",
			requestBody: &api.RouteRequest{
				Description: "Empty net id",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "",
				Metric:      100,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "Create route with metric 0",
			requestBody: &api.RouteRequest{
				Description: "Zero metric",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "zeroMetric",
				Metric:      0,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "Create route with metric 10000",
			requestBody: &api.RouteRequest{
				Description: "High metric",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "highMetric",
				Metric:      10000,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/routes", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Route{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify route exists in DB with correct fields
					db := testing_tools.GetDB(t, am.GetStore())
					dbRoute := testing_tools.VerifyRouteInDB(t, db, route.ID(got.Id))
					assert.Equal(t, tc.requestBody.Description, dbRoute.Description)
					assert.Equal(t, tc.requestBody.Metric, dbRoute.Metric)
					assert.Equal(t, tc.requestBody.Masquerade, dbRoute.Masquerade)
					assert.Equal(t, tc.requestBody.Enabled, dbRoute.Enabled)
					assert.Equal(t, route.NetID(tc.requestBody.NetworkId), dbRoute.NetID)
				}
			})
		}
	}
}

func Test_Routes_Update(t *testing.T) {
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

	networkCIDR := "10.0.0.0/24"
	peerID := testing_tools.TestPeerId

	tt := []struct {
		name           string
		routeId        string
		requestBody    *api.RouteRequest
		expectedStatus int
		verifyResponse func(t *testing.T, route *api.Route)
	}{
		{
			name:    "Update route description",
			routeId: "testRouteId",
			requestBody: &api.RouteRequest{
				Description: "Updated description",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "testNet",
				Metric:      100,
				Masquerade:  true,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, route *api.Route) {
				t.Helper()
				assert.Equal(t, "testRouteId", route.Id)
				assert.Equal(t, "Updated description", route.Description)
			},
		},
		{
			name:    "Update route metric",
			routeId: "testRouteId",
			requestBody: &api.RouteRequest{
				Description: "Test Network Route",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "testNet",
				Metric:      500,
				Masquerade:  true,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, route *api.Route) {
				t.Helper()
				assert.Equal(t, 500, route.Metric)
			},
		},
		{
			name:    "Update non-existing route",
			routeId: "nonExistingRouteId",
			requestBody: &api.RouteRequest{
				Description: "whatever",
				Network:     &networkCIDR,
				Peer:        &peerID,
				NetworkId:   "testNet",
				Metric:      100,
				Enabled:     true,
				Groups:      []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/routes/{routeId}", "{routeId}", tc.routeId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Route{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify updated route in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbRoute := testing_tools.VerifyRouteInDB(t, db, route.ID(got.Id))
					assert.Equal(t, tc.requestBody.Description, dbRoute.Description)
					assert.Equal(t, tc.requestBody.Metric, dbRoute.Metric)
					assert.Equal(t, tc.requestBody.Masquerade, dbRoute.Masquerade)
					assert.Equal(t, tc.requestBody.Enabled, dbRoute.Enabled)
				}
			})
		}
	}
}

func Test_Routes_Delete(t *testing.T) {
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
		routeId        string
		expectedStatus int
	}{
		{
			name:           "Delete existing route",
			routeId:        "testRouteId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing route",
			routeId:        "nonExistingRouteId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/routes/{routeId}", "{routeId}", tc.routeId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify route was deleted from DB for successful deletes
				if tc.expectedStatus == http.StatusOK && user.expectResponse {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyRouteNotInDB(t, db, route.ID(tc.routeId))
				}
			})
		}
	}
}
