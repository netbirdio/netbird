package http

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

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/api"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"

	"github.com/gorilla/mux"
	"github.com/magiconair/properties/assert"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
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

var testingAccount = &server.Account{
	Id:     testAccountID,
	Domain: "hotmail.com",
	Peers: map[string]*nbpeer.Peer{
		existingPeerID: {
			Key: existingPeerKey,
			IP:  netip.MustParseAddr(existingPeerIP1).AsSlice(),
			ID:  existingPeerID,
			Meta: nbpeer.PeerSystemMeta{
				GoOS: "linux",
			},
		},
		nonLinuxExistingPeerID: {
			Key: nonLinuxExistingPeerID,
			IP:  netip.MustParseAddr(existingPeerIP2).AsSlice(),
			ID:  nonLinuxExistingPeerID,
			Meta: nbpeer.PeerSystemMeta{
				GoOS: "darwin",
			},
		},
	},
	Users: map[string]*server.User{
		"test_user": server.NewAdminUser("test_user"),
	},
}

func initRoutesTestData() *RoutesHandler {
	return &RoutesHandler{
		accountManager: &mock_server.MockAccountManager{
			GetRouteFunc: func(_ context.Context, _ string, routeID route.ID, _ string) (*route.Route, error) {
				if routeID == existingRouteID {
					return baseExistingRoute, nil
				}
				if routeID == existingRouteID2 {
					route := baseExistingRoute.Copy()
					route.PeerGroups = []string{existingGroupID}
					return route, nil
				} else if routeID == existingRouteID3 {
					route := baseExistingRoute.Copy()
					route.Domains = domain.List{existingDomain}
					return route, nil
				}
				return nil, status.Errorf(status.NotFound, "route with ID %s not found", routeID)
			},
			CreateRouteFunc: func(_ context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroups []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroups []string, enabled bool, _ string, keepRoute bool) (*route.Route, error) {
				if peerID == notFoundPeerID {
					return nil, status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
				}
				if len(peerGroups) > 0 && peerGroups[0] == notFoundGroupID {
					return nil, status.Errorf(status.InvalidArgument, "peer groups with ID %s not found", peerGroups[0])
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
				}, nil
			},
			SaveRouteFunc: func(_ context.Context, _, _ string, r *route.Route) error {
				if r.Peer == notFoundPeerID {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", r.Peer)
				}
				return nil
			},
			DeleteRouteFunc: func(_ context.Context, _ string, routeID route.ID, _ string) error {
				if routeID != existingRouteID {
					return status.Errorf(status.NotFound, "Peer with ID %s not found", routeID)
				}
				return nil
			},
			GetAccountFromTokenFunc: func(_ context.Context, _ jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return testingAccount, testingAccount.Users["test_user"], nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testAccountID,
				}
			}),
		),
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
				[]byte(fmt.Sprintf(`{"Description":"Post","Network":"192.168.0.0/16","network_id":"awesomeNet","Peer":"%s","groups":["%s"]}`, existingPeerID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     toPtr("192.168.0.0/16"),
				Peer:        &existingPeerID,
				NetworkType: route.IPv4NetworkString,
				Masquerade:  false,
				Enabled:     false,
				Groups:      []string{existingGroupID},
			},
		},
		{
			name:        "Domains POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf(`{"description":"Post","domains":["example.com"],"network_id":"domainNet","peer":"%s","groups":["%s"],"keep_route":true}`, existingPeerID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "domainNet",
				Network:     toPtr("invalid Prefix"),
				KeepRoute:   true,
				Domains:     &[]string{existingDomain},
				Peer:        &existingPeerID,
				NetworkType: route.DomainNetworkString,
				Masquerade:  false,
				Enabled:     false,
				Groups:      []string{existingGroupID},
			},
		},
		{
			name:        "POST OK With Access Control Groups",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"],\"access_control_groups\":[\"%s\"]}", existingPeerID, existingGroupID, existingGroupID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:                  existingRouteID,
				Description:         "Post",
				NetworkId:           "awesomeNet",
				Network:             toPtr("192.168.0.0/16"),
				Peer:                &existingPeerID,
				NetworkType:         route.IPv4NetworkString,
				Masquerade:          false,
				Enabled:             false,
				Groups:              []string{existingGroupID},
				AccessControlGroups: &[]string{existingGroupID},
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
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\",\"groups\":[\"%s\"]}", existingPeerID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     toPtr("192.168.0.0/16"),
				Peer:        &existingPeerID,
				NetworkType: route.IPv4NetworkString,
				Masquerade:  false,
				Enabled:     false,
				Groups:      []string{existingGroupID},
			},
		},
		{
			name:           "Domains PUT OK",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf(`{"Description":"Post","domains":["example.com"],"network_id":"awesomeNet","Peer":"%s","groups":["%s"],"keep_route":true}`, existingPeerID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     toPtr("invalid Prefix"),
				Domains:     &[]string{existingDomain},
				Peer:        &existingPeerID,
				NetworkType: route.DomainNetworkString,
				Masquerade:  false,
				Enabled:     false,
				Groups:      []string{existingGroupID},
				KeepRoute:   true,
			},
		},
		{
			name:           "PUT OK when peer_groups provided",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"peer_groups\":[\"%s\"],\"groups\":[\"%s\"]}", existingGroupID, existingGroupID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     toPtr("192.168.0.0/16"),
				Peer:        &emptyString,
				PeerGroups:  &[]string{existingGroupID},
				NetworkType: route.IPv4NetworkString,
				Masquerade:  false,
				Enabled:     false,
				Groups:      []string{existingGroupID},
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

			router := mux.NewRouter()
			router.HandleFunc("/api/routes/{routeId}", p.GetRoute).Methods("GET")
			router.HandleFunc("/api/routes/{routeId}", p.DeleteRoute).Methods("DELETE")
			router.HandleFunc("/api/routes", p.CreateRoute).Methods("POST")
			router.HandleFunc("/api/routes/{routeId}", p.UpdateRoute).Methods("PUT")
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

func TestValidateDomains(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected domain.List
		wantErr  bool
	}{
		{
			name:     "Empty list",
			domains:  nil,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Valid ASCII domain",
			domains:  []string{"sub.ex-ample.com"},
			expected: domain.List{"sub.ex-ample.com"},
			wantErr:  false,
		},
		{
			name:     "Valid Unicode domain",
			domains:  []string{"münchen.de"},
			expected: domain.List{"xn--mnchen-3ya.de"},
			wantErr:  false,
		},
		{
			name:     "Valid Unicode, all labels",
			domains:  []string{"中国.中国.中国"},
			expected: domain.List{"xn--fiqs8s.xn--fiqs8s.xn--fiqs8s"},
			wantErr:  false,
		},
		{
			name:     "With underscores",
			domains:  []string{"_jabber._tcp.gmail.com"},
			expected: domain.List{"_jabber._tcp.gmail.com"},
			wantErr:  false,
		},
		{
			name:     "Invalid domain format",
			domains:  []string{"-example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid domain format 2",
			domains:  []string{"example.com-"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Multiple domains valid and invalid",
			domains:  []string{"google.com", "invalid,nbdomain.com", "münchen.de"},
			expected: domain.List{"google.com"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateDomains(tt.domains)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, got, tt.expected)
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

func toPtr[T any](v T) *T {
	return &v
}
