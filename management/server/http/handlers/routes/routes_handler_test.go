package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	existingRouteID         = "existingRouteID"
	existingRouteID2        = "existingRouteID2" // for peer_groups test
	existingRouteID3        = "existingRouteID3" // for domains test
	notFoundRouteID         = "notFoundRouteID"
	existingPeerIP1         = "100.64.0.100"
	existingPeerIP2         = "100.64.0.101"
	notFoundPeerID          = "nonExistingPeer"
	existingPeerKey         = "existingPeerKey"
	nonLinuxExistingPeerKey = "darwinExistingPeerKey"
	testAccountID           = "test_id"
	existingGroupID         = "testGroup"
	notFoundGroupID         = "nonExistingGroup"
	existingDomain          = "example.com"
)

var emptyString = ""
var existingPeerID = "peer-id"
var nonLinuxExistingPeerID = "darwin-peer-id"

var baseExistingRoute = &route.Route{
	ID:          existingRouteID,
	Description: "base route",
	NetID:       "awesomeNet",
	Network:     netip.MustParsePrefix("192.168.0.0/24"),
	Domains:     domain.List{},
	KeepRoute:   false,
	NetworkType: route.IPv4Network,
	Metric:      9999,
	Masquerade:  false,
	Enabled:     true,
	Groups:      []string{existingGroupID},
}

func initRoutesTestData() *handler {
	return &handler{
		accountManager: &mock_server.MockAccountManager{
			GetRouteFunc: func(_ context.Context, _ string, routeID route.ID, _ string) (*route.Route, error) {
				switch routeID {
				case existingRouteID:
					return baseExistingRoute, nil
				case existingRouteID2:
					route := baseExistingRoute.Copy()
					route.PeerGroups = []string{existingGroupID}
					return route, nil
				case existingRouteID3:
					route := baseExistingRoute.Copy()
					route.Domains = domain.List{existingDomain}
					return route, nil
				default:
					return nil, status.Errorf(status.NotFound, "route with ID %s not found", routeID)
				}
			},
			CreateRouteFunc: func(_ context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroups []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroups []string, enabled bool, _ string, keepRoute bool, skipAutoApply bool) (*route.Route, error) {
				if peerID == notFoundPeerID {
					return nil, status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
				}
				if len(peerGroups) > 0 && peerGroups[0] == notFoundGroupID {
					return nil, status.Errorf(status.InvalidArgument, "peer groups with ID %s not found", peerGroups[0])
				}
				if peerID != "" {
					if peerID == nonLinuxExistingPeerID {
						return nil, status.Errorf(status.InvalidArgument, "non-linux peers are not supported as network routes")
					}
				}

				return &route.Route{
					ID:                  existingRouteID,
					NetID:               netID,
					Peer:                peerID,
					PeerGroups:          peerGroups,
					Network:             prefix,
					Domains:             domains,
					NetworkType:         networkType,
					Description:         description,
					Masquerade:          masquerade,
					Enabled:             enabled,
					Groups:              groups,
					KeepRoute:           keepRoute,
					AccessControlGroups: accessControlGroups,
					SkipAutoApply:       skipAutoApply,
				}, nil
			},
			SaveRouteFunc: func(_ context.Context, _, _ string, r *route.Route) error {
				if r.Peer == notFoundPeerID {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", r.Peer)
				}

				if r.Peer == nonLinuxExistingPeerID {
					return status.Errorf(status.InvalidArgument, "non-linux peers are not supported as network routes")
				}

				return nil
			},
			DeleteRouteFunc: func(_ context.Context, _ string, routeID route.ID, _ string) error {
				if routeID != existingRouteID {
					return status.Errorf(status.NotFound, "Peer with ID %s not found", routeID)
				}
				return nil
			},
		},
	}
}

func TestRoutesHandlers(t *testing.T) {
	baseExistingRouteWithPeerGroups := baseExistingRoute.Copy()
	baseExistingRouteWithPeerGroups.PeerGroups = []string{existingGroupID}

	baseExistingRouteWithDomains := baseExistingRoute.Copy()
	baseExistingRouteWithDomains.Domains = domain.List{existingDomain}

	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedRoute  *api.Route
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "Get Existing Route",
			requestType:    http.MethodGet,
			requestPath:    "/api/routes/" + existingRouteID,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute:  toApiRoute(t, baseExistingRoute),
		},
		{
			name:           "Get Not Existing Route",
			requestType:    http.MethodGet,
			requestPath:    "/api/routes/" + notFoundRouteID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Get Existing Route with Peer Groups",
			requestType:    http.MethodGet,
			requestPath:    "/api/routes/" + existingRouteID2,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute:  toApiRoute(t, baseExistingRouteWithPeerGroups),
		},
		{
			name:           "Get Existing Route with Domains",
			requestType:    http.MethodGet,
			requestPath:    "/api/routes/" + existingRouteID3,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute:  toApiRoute(t, baseExistingRouteWithDomains),
		},
		{
			name:           "Delete Existing Route",
			requestType:    http.MethodDelete,
			requestPath:    "/api/routes/" + existingRouteID,
			expectedStatus: http.StatusOK,
			expectedBody:   false,
		},
		{
			name:           "Delete Not Existing Route",
			requestType:    http.MethodDelete,
			requestPath:    "/api/routes/" + notFoundRouteID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "Network POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","Network":"192.168.0.0/16","network_id":"awesomeNet","Peer":"%s","groups":["%s"],"skip_auto_apply":false}`, existingPeerID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:            existingRouteID,
				Description:   "Post",
				NetworkId:     "awesomeNet",
				Network:       util.ToPtr("192.168.0.0/16"),
				Peer:          &existingPeerID,
				NetworkType:   route.IPv4NetworkString,
				Masquerade:    false,
				Enabled:       false,
				Groups:        []string{existingGroupID},
				SkipAutoApply: util.ToPtr(false),
			},
		},
		{
			name:        "Domains POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"description":"Post","domains":["example.com"],"network_id":"domainNet","peer":"%s","groups":["%s"],"keep_route":true,"skip_auto_apply":false}`, existingPeerID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:            existingRouteID,
				Description:   "Post",
				NetworkId:     "domainNet",
				Network:       util.ToPtr("invalid Prefix"),
				KeepRoute:     true,
				Domains:       &[]string{existingDomain},
				Peer:          &existingPeerID,
				NetworkType:   route.DomainNetworkString,
				Masquerade:    false,
				Enabled:       false,
				Groups:        []string{existingGroupID},
				SkipAutoApply: util.ToPtr(false),
			},
		},
		{
			name:        "POST OK With Access Control Groups",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"],\"access_control_groups\":[\"%s\"],\"skip_auto_apply\":false}", existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:                  existingRouteID,
				Description:         "Post",
				NetworkId:           "awesomeNet",
				Network:             util.ToPtr("192.168.0.0/16"),
				Peer:                &existingPeerID,
				NetworkType:         route.IPv4NetworkString,
				Masquerade:          false,
				Enabled:             false,
				Groups:              []string{existingGroupID},
				AccessControlGroups: &[]string{existingGroupID},
				SkipAutoApply:       util.ToPtr(false),
			},
		},
		{
			name:           "POST Non Linux Peer",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", nonLinuxExistingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Not Found Peer",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", notFoundPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Invalid Network Identifier",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"12345678901234567890qwertyuiopqwertyuiop1\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Invalid Network",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/34\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Invalid Domains",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf(`{"Description":"Post","domains":["-example.com"],"network_id":"awesomeNet","Peer":"%s","groups":["%s"]}`, existingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Wildcard Domain",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf(`{"Description":"Post","domains":["*.example.com"],"network_id":"awesomeNet","Peer":"%s","groups":["%s"]}`, existingPeerID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   false,
		},
		{
			name:        "POST UnprocessableEntity when both network and domains are provided",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","Network":"192.168.0.0/16","domains":["example.com"],"network_id":"awesomeNet","peer":"%s","peer_groups":["%s"],"groups":["%s"]}`, existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "POST UnprocessableEntity when no network and domains are provided",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","network_id":"awesomeNet","groups":["%s"]}`, existingPeerID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "POST UnprocessableEntity when both peer and peer_groups are provided",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"peer\":\"%s\",\"peer_groups\":[\"%s\"],\"groups\":[\"%s\"]}", existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "POST UnprocessableEntity when no peer and peer_groups are provided",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"groups\":[\"%s\"]}", existingPeerID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "Network PUT OK",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"],\"is_selected\":true}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:            existingRouteID,
				Description:   "Post",
				NetworkId:     "awesomeNet",
				Network:       util.ToPtr("192.168.0.0/16"),
				Peer:          &existingPeerID,
				NetworkType:   route.IPv4NetworkString,
				Masquerade:    false,
				Enabled:       false,
				Groups:        []string{existingGroupID},
				SkipAutoApply: util.ToPtr(false),
			},
		},
		{
			name:           "Domains PUT OK",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf(`{"Description":"Post","domains":["example.com"],"network_id":"awesomeNet","Peer":"%s","groups":["%s"],"keep_route":true,"skip_auto_apply":false}`, existingPeerID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:            existingRouteID,
				Description:   "Post",
				NetworkId:     "awesomeNet",
				Network:       util.ToPtr("invalid Prefix"),
				Domains:       &[]string{existingDomain},
				Peer:          &existingPeerID,
				NetworkType:   route.DomainNetworkString,
				Masquerade:    false,
				Enabled:       false,
				Groups:        []string{existingGroupID},
				KeepRoute:     true,
				SkipAutoApply: util.ToPtr(false),
			},
		},
		{
			name:           "PUT OK when peer_groups provided",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"peer_groups\":[\"%s\"],\"groups\":[\"%s\"],\"skip_auto_apply\":false}", existingGroupID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:            existingRouteID,
				Description:   "Post",
				NetworkId:     "awesomeNet",
				Network:       util.ToPtr("192.168.0.0/16"),
				Peer:          &emptyString,
				PeerGroups:    &[]string{existingGroupID},
				NetworkType:   route.IPv4NetworkString,
				Masquerade:    false,
				Enabled:       false,
				Groups:        []string{existingGroupID},
				SkipAutoApply: util.ToPtr(false),
			},
		},
		{
			name:           "PUT Not Found Route",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + notFoundRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:           "PUT Not Found Peer",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", notFoundPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "PUT Non Linux Peer",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", nonLinuxExistingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "PUT Invalid Network Identifier",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"12345678901234567890qwertyuiopqwertyuiop1\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "PUT Invalid Network",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/34\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT Invalid Domains",
			requestType: http.MethodPut,
			requestPath: "/api/routes/" + existingRouteID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","domains":["-example.com"],"network_id":"awesomeNet","peer":"%s","peer_groups":["%s"],"groups":["%s"]}`, existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT UnprocessableEntity when both network and domains are provided",
			requestType: http.MethodPut,
			requestPath: "/api/routes/" + existingRouteID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","Network":"192.168.0.0/16","domains":["example.com"],"network_id":"awesomeNet","peer":"%s","peer_groups":["%s"],"groups":["%s"]}`, existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT UnprocessableEntity when no network and domains are provided",
			requestType: http.MethodPut,
			requestPath: "/api/routes/" + existingRouteID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"Description":"Post","network_id":"awesomeNet","peer":"%s","peer_groups":["%s"],"groups":["%s"]}`, existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT UnprocessableEntity when both peer and peer_groups are provided",
			requestType: http.MethodPut,
			requestPath: "/api/routes/" + existingRouteID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"peer\":\"%s\",\"peer_groups\":[\"%s\"],\"groups\":[\"%s\"]}", existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT UnprocessableEntity when no peer and peer_groups are provided",
			requestType: http.MethodPut,
			requestPath: "/api/routes/" + existingRouteID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"groups\":[\"%s\"]}", existingPeerID))),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
	}

	p := initRoutesTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "test_user",
				Domain:    "hotmail.com",
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/routes/{routeId}", p.getRoute).Methods("GET")
			router.HandleFunc("/api/routes/{routeId}", p.deleteRoute).Methods("DELETE")
			router.HandleFunc("/api/routes", p.createRoute).Methods("POST")
			router.HandleFunc("/api/routes/{routeId}", p.updateRoute).Methods("PUT")
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

			got := &api.Route{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			assert.Equal(t, got, tc.expectedRoute)
		})
	}
}

func toApiRoute(t *testing.T, r *route.Route) *api.Route {
	t.Helper()

	apiRoute, err := toRouteResponse(r)
	// json flattens pointer to nil slices to null
	if apiRoute.Domains != nil && *apiRoute.Domains == nil {
		apiRoute.Domains = nil
	}
	require.NoError(t, err, "Failed to convert route")
	return apiRoute
}
