//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Networks_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all networks", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.Network{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testNetworkId", got[0].Id)
			assert.Equal(t, "testNetwork", got[0].Name)
			assert.Equal(t, "test network description", *got[0].Description)
			assert.GreaterOrEqual(t, len(got[0].Routers), 1)
			assert.GreaterOrEqual(t, len(got[0].Resources), 1)
			assert.GreaterOrEqual(t, got[0].RoutingPeersCount, 1)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Networks_GetById(t *testing.T) {
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
		networkId      string
		expectedStatus int
		expectNetwork  bool
	}{
		{
			name:           "Get existing network",
			networkId:      "testNetworkId",
			expectedStatus: http.StatusOK,
			expectNetwork:  true,
		},
		{
			name:           "Get non-existing network",
			networkId:      "nonExistingNetworkId",
			expectedStatus: http.StatusNotFound,
			expectNetwork:  false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/networks/{networkId}", "{networkId}", tc.networkId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectNetwork {
					got := &api.Network{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, tc.networkId, got.Id)
					assert.Equal(t, "testNetwork", got.Name)
					assert.Equal(t, "test network description", *got.Description)
					assert.GreaterOrEqual(t, len(got.Routers), 1)
					assert.GreaterOrEqual(t, len(got.Resources), 1)
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

func Test_Networks_Create(t *testing.T) {
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

	desc := "new network description"

	tt := []struct {
		name           string
		requestBody    *api.NetworkRequest
		expectedStatus int
		verifyResponse func(t *testing.T, network *api.Network)
	}{
		{
			name: "Create network with name and description",
			requestBody: &api.NetworkRequest{
				Name:        "newNetwork",
				Description: &desc,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, network *api.Network) {
				t.Helper()
				assert.NotEmpty(t, network.Id)
				assert.Equal(t, "newNetwork", network.Name)
				assert.Equal(t, "new network description", *network.Description)
				assert.Empty(t, network.Routers)
				assert.Empty(t, network.Resources)
				assert.Equal(t, 0, network.RoutingPeersCount)
			},
		},
		{
			name: "Create network with name only",
			requestBody: &api.NetworkRequest{
				Name: "simpleNetwork",
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, network *api.Network) {
				t.Helper()
				assert.NotEmpty(t, network.Id)
				assert.Equal(t, "simpleNetwork", network.Name)
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/networks", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Network{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_Networks_Update(t *testing.T) {
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

	updatedDesc := "updated description"

	tt := []struct {
		name           string
		networkId      string
		requestBody    *api.NetworkRequest
		expectedStatus int
		verifyResponse func(t *testing.T, network *api.Network)
	}{
		{
			name:      "Update network name",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRequest{
				Name:        "updatedNetwork",
				Description: &updatedDesc,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, network *api.Network) {
				t.Helper()
				assert.Equal(t, "testNetworkId", network.Id)
				assert.Equal(t, "updatedNetwork", network.Name)
				assert.Equal(t, "updated description", *network.Description)
			},
		},
		{
			name:      "Update non-existing network",
			networkId: "nonExistingNetworkId",
			requestBody: &api.NetworkRequest{
				Name: "whatever",
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/networks/{networkId}", "{networkId}", tc.networkId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Network{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_Networks_Delete(t *testing.T) {
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
		networkId      string
		expectedStatus int
	}{
		{
			name:           "Delete existing network",
			networkId:      "testNetworkId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing network",
			networkId:      "nonExistingNetworkId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/networks/{networkId}", "{networkId}", tc.networkId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_Networks_Delete_Cascades(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

	// Delete the network
	req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, "/api/networks/testNetworkId", testing_tools.TestAdminId)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)
	testing_tools.ReadResponse(t, recorder, http.StatusOK, true)

	// Verify network is gone
	req = testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/testNetworkId", testing_tools.TestAdminId)
	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)
	testing_tools.ReadResponse(t, recorder, http.StatusNotFound, true)

	// Verify routers in that network are gone
	req = testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/testNetworkId/routers", testing_tools.TestAdminId)
	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)
	content, _ := testing_tools.ReadResponse(t, recorder, http.StatusOK, true)
	var routers []*api.NetworkRouter
	require.NoError(t, json.Unmarshal(content, &routers))
	assert.Empty(t, routers)

	// Verify resources in that network are gone
	req = testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/testNetworkId/resources", testing_tools.TestAdminId)
	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)
	content, _ = testing_tools.ReadResponse(t, recorder, http.StatusOK, true)
	var resources []*api.NetworkResource
	require.NoError(t, json.Unmarshal(content, &resources))
	assert.Empty(t, resources)
}

func Test_NetworkResources_GetAllInNetwork(t *testing.T) {
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
		t.Run(user.name+" - Get all resources in network", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/testNetworkId/resources", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.NetworkResource{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testResourceId", got[0].Id)
			assert.Equal(t, "testResource", got[0].Name)
			assert.Equal(t, api.NetworkResourceType("host"), got[0].Type)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_NetworkResources_GetAllInAccount(t *testing.T) {
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
		t.Run(user.name+" - Get all resources in account", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/resources", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.NetworkResource{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 1)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_NetworkResources_GetById(t *testing.T) {
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
		networkId      string
		resourceId     string
		expectedStatus int
		expectResource bool
	}{
		{
			name:           "Get existing resource",
			networkId:      "testNetworkId",
			resourceId:     "testResourceId",
			expectedStatus: http.StatusOK,
			expectResource: true,
		},
		{
			name:           "Get non-existing resource",
			networkId:      "testNetworkId",
			resourceId:     "nonExistingResourceId",
			expectedStatus: http.StatusNotFound,
			expectResource: false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

				path := fmt.Sprintf("/api/networks/%s/resources/%s", tc.networkId, tc.resourceId)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectResource {
					got := &api.NetworkResource{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, tc.resourceId, got.Id)
					assert.Equal(t, "testResource", got.Name)
					assert.Equal(t, api.NetworkResourceType("host"), got.Type)
					assert.Equal(t, "3.3.3.3/32", got.Address)
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

func Test_NetworkResources_Create(t *testing.T) {
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

	desc := "new resource"

	tt := []struct {
		name           string
		networkId      string
		requestBody    *api.NetworkResourceRequest
		expectedStatus int
		verifyResponse func(t *testing.T, resource *api.NetworkResource)
	}{
		{
			name:      "Create host resource with IP",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:        "hostResource",
				Description: &desc,
				Address:     "1.1.1.1",
				Groups:      []string{testing_tools.TestGroupId},
				Enabled:     true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.NotEmpty(t, resource.Id)
				assert.Equal(t, "hostResource", resource.Name)
				assert.Equal(t, api.NetworkResourceType("host"), resource.Type)
				assert.Equal(t, "1.1.1.1/32", resource.Address)
				assert.True(t, resource.Enabled)
			},
		},
		{
			name:      "Create host resource with CIDR /32",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "hostCIDR",
				Address: "10.0.0.1/32",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("host"), resource.Type)
				assert.Equal(t, "10.0.0.1/32", resource.Address)
			},
		},
		{
			name:      "Create subnet resource",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "subnetResource",
				Address: "192.168.0.0/24",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("subnet"), resource.Type)
				assert.Equal(t, "192.168.0.0/24", resource.Address)
			},
		},
		{
			name:      "Create domain resource",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "domainResource",
				Address: "example.com",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("domain"), resource.Type)
				assert.Equal(t, "example.com", resource.Address)
			},
		},
		{
			name:      "Create wildcard domain resource",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "wildcardDomain",
				Address: "*.example.com",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("domain"), resource.Type)
				assert.Equal(t, "*.example.com", resource.Address)
			},
		},
		{
			name:      "Create disabled resource",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "disabledResource",
				Address: "5.5.5.5",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.False(t, resource.Enabled)
			},
		},
		{
			name:      "Create resource with invalid address",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "invalidResource",
				Address: "not-a-valid-address!!!",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:      "Create resource with empty groups",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "noGroupsResource",
				Address: "7.7.7.7",
				Groups:  []string{},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.NotEmpty(t, resource.Id)
			},
		},
		{
			name:      "Create resource with duplicate name",
			networkId: "testNetworkId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "testResource",
				Address: "8.8.8.8",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				path := fmt.Sprintf("/api/networks/%s/resources", tc.networkId)
				req := testing_tools.BuildRequest(t, body, http.MethodPost, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NetworkResource{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_NetworkResources_Update(t *testing.T) {
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

	updatedDesc := "updated resource"

	tt := []struct {
		name           string
		networkId      string
		resourceId     string
		requestBody    *api.NetworkResourceRequest
		expectedStatus int
		verifyResponse func(t *testing.T, resource *api.NetworkResource)
	}{
		{
			name:       "Update resource name and address",
			networkId:  "testNetworkId",
			resourceId: "testResourceId",
			requestBody: &api.NetworkResourceRequest{
				Name:        "updatedResource",
				Description: &updatedDesc,
				Address:     "4.4.4.4",
				Groups:      []string{testing_tools.TestGroupId},
				Enabled:     true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, "testResourceId", resource.Id)
				assert.Equal(t, "updatedResource", resource.Name)
				assert.Equal(t, "updated resource", *resource.Description)
				assert.Equal(t, "4.4.4.4/32", resource.Address)
			},
		},
		{
			name:       "Update resource to subnet type",
			networkId:  "testNetworkId",
			resourceId: "testResourceId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "testResource",
				Address: "10.0.0.0/16",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("subnet"), resource.Type)
				assert.Equal(t, "10.0.0.0/16", resource.Address)
			},
		},
		{
			name:       "Update resource to domain type",
			networkId:  "testNetworkId",
			resourceId: "testResourceId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "testResource",
				Address: "myservice.example.com",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, resource *api.NetworkResource) {
				t.Helper()
				assert.Equal(t, api.NetworkResourceType("domain"), resource.Type)
				assert.Equal(t, "myservice.example.com", resource.Address)
			},
		},
		{
			name:       "Update non-existing resource",
			networkId:  "testNetworkId",
			resourceId: "nonExistingResourceId",
			requestBody: &api.NetworkResourceRequest{
				Name:    "whatever",
				Address: "1.2.3.4",
				Groups:  []string{testing_tools.TestGroupId},
				Enabled: true,
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				path := fmt.Sprintf("/api/networks/%s/resources/%s", tc.networkId, tc.resourceId)
				req := testing_tools.BuildRequest(t, body, http.MethodPut, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NetworkResource{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_NetworkResources_Delete(t *testing.T) {
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
		networkId      string
		resourceId     string
		expectedStatus int
	}{
		{
			name:           "Delete existing resource",
			networkId:      "testNetworkId",
			resourceId:     "testResourceId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing resource",
			networkId:      "testNetworkId",
			resourceId:     "nonExistingResourceId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				path := fmt.Sprintf("/api/networks/%s/resources/%s", tc.networkId, tc.resourceId)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_NetworkRouters_GetAllInNetwork(t *testing.T) {
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
		t.Run(user.name+" - Get all routers in network", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/testNetworkId/routers", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.NetworkRouter{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testRouterId", got[0].Id)
			assert.Equal(t, "testPeerId", *got[0].Peer)
			assert.True(t, got[0].Masquerade)
			assert.Equal(t, 100, got[0].Metric)
			assert.True(t, got[0].Enabled)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_NetworkRouters_GetAllInAccount(t *testing.T) {
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
		t.Run(user.name+" - Get all routers in account", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/networks/routers", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.NetworkRouter{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 1)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_NetworkRouters_GetById(t *testing.T) {
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
		networkId      string
		routerId       string
		expectedStatus int
		expectRouter   bool
	}{
		{
			name:           "Get existing router",
			networkId:      "testNetworkId",
			routerId:       "testRouterId",
			expectedStatus: http.StatusOK,
			expectRouter:   true,
		},
		{
			name:           "Get non-existing router",
			networkId:      "testNetworkId",
			routerId:       "nonExistingRouterId",
			expectedStatus: http.StatusNotFound,
			expectRouter:   false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, true)

				path := fmt.Sprintf("/api/networks/%s/routers/%s", tc.networkId, tc.routerId)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectRouter {
					got := &api.NetworkRouter{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, tc.routerId, got.Id)
					assert.Equal(t, "testPeerId", *got.Peer)
					assert.True(t, got.Masquerade)
					assert.Equal(t, 100, got.Metric)
					assert.True(t, got.Enabled)
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

func Test_NetworkRouters_Create(t *testing.T) {
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

	peerID := "testPeerId"
	peerGroups := []string{testing_tools.TestGroupId}

	tt := []struct {
		name           string
		networkId      string
		requestBody    *api.NetworkRouterRequest
		expectedStatus int
		verifyResponse func(t *testing.T, router *api.NetworkRouter)
	}{
		{
			name:      "Create router with peer",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: true,
				Metric:     200,
				Enabled:    true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.NotEmpty(t, router.Id)
				assert.Equal(t, peerID, *router.Peer)
				assert.True(t, router.Masquerade)
				assert.Equal(t, 200, router.Metric)
				assert.True(t, router.Enabled)
			},
		},
		{
			name:      "Create router with peer groups",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRouterRequest{
				PeerGroups: &peerGroups,
				Masquerade: false,
				Metric:     300,
				Enabled:    true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.NotEmpty(t, router.Id)
				assert.NotNil(t, router.PeerGroups)
				assert.Equal(t, 1, len(*router.PeerGroups))
				assert.False(t, router.Masquerade)
				assert.Equal(t, 300, router.Metric)
				assert.True(t, router.Enabled) // always true on creation
			},
		},
		{
			name:      "Create router with both peer and peer_groups",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				PeerGroups: &peerGroups,
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "Create router without peer and peer_groups",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRouterRequest{
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "Create router in non-existing network",
			networkId: "nonExistingNetworkId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:      "Create router enabled is always true",
			networkId: "testNetworkId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: false,
				Metric:     50,
				Enabled:    false, // handler sets to true
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.True(t, router.Enabled) // always true on creation
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				path := fmt.Sprintf("/api/networks/%s/routers", tc.networkId)
				req := testing_tools.BuildRequest(t, body, http.MethodPost, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NetworkRouter{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_NetworkRouters_Update(t *testing.T) {
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

	peerID := "testPeerId"
	peerGroups := []string{testing_tools.TestGroupId}

	tt := []struct {
		name           string
		networkId      string
		routerId       string
		requestBody    *api.NetworkRouterRequest
		expectedStatus int
		verifyResponse func(t *testing.T, router *api.NetworkRouter)
	}{
		{
			name:      "Update router metric and masquerade",
			networkId: "testNetworkId",
			routerId:  "testRouterId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: false,
				Metric:     500,
				Enabled:    true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.Equal(t, "testRouterId", router.Id)
				assert.False(t, router.Masquerade)
				assert.Equal(t, 500, router.Metric)
			},
		},
		{
			name:      "Update router to use peer groups",
			networkId: "testNetworkId",
			routerId:  "testRouterId",
			requestBody: &api.NetworkRouterRequest{
				PeerGroups: &peerGroups,
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.NotNil(t, router.PeerGroups)
				assert.Equal(t, 1, len(*router.PeerGroups))
			},
		},
		{
			name:      "Update router disabled",
			networkId: "testNetworkId",
			routerId:  "testRouterId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: true,
				Metric:     100,
				Enabled:    false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.False(t, router.Enabled)
			},
		},
		{
			name:      "Update non-existing router creates it",
			networkId: "testNetworkId",
			routerId:  "nonExistingRouterId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, router *api.NetworkRouter) {
				t.Helper()
				assert.Equal(t, "nonExistingRouterId", router.Id)
			},
		},
		{
			name:      "Update router with both peer and peer_groups",
			networkId: "testNetworkId",
			routerId:  "testRouterId",
			requestBody: &api.NetworkRouterRequest{
				Peer:       &peerID,
				PeerGroups: &peerGroups,
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "Update router without peer and peer_groups",
			networkId: "testNetworkId",
			routerId:  "testRouterId",
			requestBody: &api.NetworkRouterRequest{
				Masquerade: true,
				Metric:     100,
				Enabled:    true,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)

				path := fmt.Sprintf("/api/networks/%s/routers/%s", tc.networkId, tc.routerId)
				req := testing_tools.BuildRequest(t, body, http.MethodPut, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.NetworkRouter{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}
			})
		}
	}
}

func Test_NetworkRouters_Delete(t *testing.T) {
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
		networkId      string
		routerId       string
		expectedStatus int
	}{
		{
			name:           "Delete existing router",
			networkId:      "testNetworkId",
			routerId:       "testRouterId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing router",
			networkId:      "testNetworkId",
			routerId:       "nonExistingRouterId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/networks.sql", nil, false)

				path := fmt.Sprintf("/api/networks/%s/routers/%s", tc.networkId, tc.routerId)
				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}
