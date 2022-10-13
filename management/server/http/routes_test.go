package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

const (
	existingRouteID = "existingRouteID"
	notFoundRouteID = "notFoundRouteID"
	existingPeerID  = "100.64.0.100"
	notFoundPeerID  = "100.64.0.200"
	existingPeerKey = "existingPeerKey"
	testAccountID   = "test_id"
)

var baseExistingRoute = &route.Route{
	ID:          existingRouteID,
	Description: "base route",
	NetID:       "awesomeNet",
	Network:     netip.MustParsePrefix("192.168.0.0/24"),
	NetworkType: route.IPv4Network,
	Metric:      9999,
	Masquerade:  false,
	Enabled:     true,
}

var testingAccount = &server.Account{
	Id:     testAccountID,
	Domain: "hotmail.com",
	Peers: map[string]*server.Peer{
		existingPeerKey: {
			Key: existingPeerID,
			IP:  netip.MustParseAddr(existingPeerID).AsSlice(),
		},
	},
}

func initRoutesTestData() *Routes {
	return &Routes{
		accountManager: &mock_server.MockAccountManager{
			GetRouteFunc: func(_, routeID string) (*route.Route, error) {
				if routeID == existingRouteID {
					return baseExistingRoute, nil
				}
				return nil, status.Errorf(codes.NotFound, "route with ID %s not found", routeID)
			},
			CreateRouteFunc: func(accountID string, network, peer, description, netID string, masquerade bool, metric int, enabled bool) (*route.Route, error) {
				networkType, p, _ := route.ParseNetwork(network)
				return &route.Route{
					ID:          existingRouteID,
					NetID:       netID,
					Peer:        peer,
					Network:     p,
					NetworkType: networkType,
					Description: description,
					Masquerade:  masquerade,
					Enabled:     enabled,
				}, nil
			},
			SaveRouteFunc: func(_ string, _ *route.Route) error {
				return nil
			},
			DeleteRouteFunc: func(_ string, peerIP string) error {
				if peerIP != existingRouteID {
					return status.Errorf(codes.NotFound, "Peer with ID %s not found", peerIP)
				}
				return nil
			},
			GetPeerByIPFunc: func(_ string, peerIP string) (*server.Peer, error) {
				if peerIP != existingPeerID {
					return nil, status.Errorf(codes.NotFound, "Peer with ID %s not found", peerIP)
				}
				return &server.Peer{
					Key: existingPeerKey,
					IP:  netip.MustParseAddr(existingPeerID).AsSlice(),
				}, nil
			},
			UpdateRouteFunc: func(_ string, routeID string, operations []server.RouteUpdateOperation) (*route.Route, error) {
				routeToUpdate := baseExistingRoute
				if routeID != routeToUpdate.ID {
					return nil, status.Errorf(codes.NotFound, "route %s no longer exists", routeID)
				}
				for _, operation := range operations {
					switch operation.Type {
					case server.UpdateRouteNetwork:
						routeToUpdate.NetworkType, routeToUpdate.Network, _ = route.ParseNetwork(operation.Values[0])
					case server.UpdateRouteDescription:
						routeToUpdate.Description = operation.Values[0]
					case server.UpdateRouteNetworkIdentifier:
						routeToUpdate.NetID = operation.Values[0]
					case server.UpdateRoutePeer:
						routeToUpdate.Peer = operation.Values[0]
					case server.UpdateRouteMetric:
						routeToUpdate.Metric, _ = strconv.Atoi(operation.Values[0])
					case server.UpdateRouteMasquerade:
						routeToUpdate.Masquerade, _ = strconv.ParseBool(operation.Values[0])
					case server.UpdateRouteEnabled:
						routeToUpdate.Enabled, _ = strconv.ParseBool(operation.Values[0])
					default:
						return nil, fmt.Errorf("no operation")
					}
				}
				return routeToUpdate, nil
			},
			GetAccountFromTokenFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return testingAccount, nil
			},
		},
		authAudience: "",
		jwtExtractor: jwtclaims.ClaimsExtractor{
			ExtractClaimsFromRequestContext: func(r *http.Request, authAudiance string) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testAccountID,
				}
			},
		},
	}
}

func TestRoutesHandlers(t *testing.T) {
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
			expectedRoute:  toRouteResponse(testingAccount, baseExistingRoute),
		},
		{
			name:           "Get Not Existing Route",
			requestType:    http.MethodGet,
			requestPath:    "/api/routes/" + notFoundRouteID,
			expectedStatus: http.StatusNotFound,
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
			name:        "POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/routes",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     "192.168.0.0/16",
				Peer:        existingPeerID,
				NetworkType: route.IPv4NetworkString,
				Masquerade:  false,
				Enabled:     false,
			},
		},
		{
			name:           "POST Not Found Peer",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", notFoundPeerID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "POST Not Invalid Network Identifier",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"12345678901234567890qwertyuiopqwertyuiop1\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:           "POST Invalid Network",
			requestType:    http.MethodPost,
			requestPath:    "/api/routes",
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/34\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:           "PUT OK",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "Post",
				NetworkId:   "awesomeNet",
				Network:     "192.168.0.0/16",
				Peer:        existingPeerID,
				NetworkType: route.IPv4NetworkString,
				Masquerade:  false,
				Enabled:     false,
			},
		},
		{
			name:           "PUT Not Found Route",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + notFoundRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:           "PUT Not Found Peer",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", notFoundPeerID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "PUT Invalid Network Identifier",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"12345678901234567890qwertyuiopqwertyuiop1\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:           "PUT Invalid Network",
			requestType:    http.MethodPut,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/34\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:           "PATCH Description OK",
			requestType:    http.MethodPatch,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString("[{\"op\":\"replace\",\"path\":\"description\",\"value\":[\"NewDesc\"]}]"),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "NewDesc",
				NetworkId:   "awesomeNet",
				Network:     baseExistingRoute.Network.String(),
				NetworkType: route.IPv4NetworkString,
				Masquerade:  baseExistingRoute.Masquerade,
				Enabled:     baseExistingRoute.Enabled,
				Metric:      baseExistingRoute.Metric,
			},
		},
		{
			name:           "PATCH Peer OK",
			requestType:    http.MethodPatch,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("[{\"op\":\"replace\",\"path\":\"peer\",\"value\":[\"%s\"]}]", existingPeerID)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedRoute: &api.Route{
				Id:          existingRouteID,
				Description: "NewDesc",
				NetworkId:   "awesomeNet",
				Network:     baseExistingRoute.Network.String(),
				NetworkType: route.IPv4NetworkString,
				Peer:        existingPeerID,
				Masquerade:  baseExistingRoute.Masquerade,
				Enabled:     baseExistingRoute.Enabled,
				Metric:      baseExistingRoute.Metric,
			},
		},
		{
			name:           "PATCH Not Found Peer",
			requestType:    http.MethodPatch,
			requestPath:    "/api/routes/" + existingRouteID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("[{\"op\":\"replace\",\"path\":\"peer\",\"value\":[\"%s\"]}]", notFoundPeerID)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:           "PATCH Not Found Route",
			requestType:    http.MethodPatch,
			requestPath:    "/api/routes/" + notFoundRouteID,
			requestBody:    bytes.NewBufferString("[{\"op\":\"replace\",\"path\":\"network\",\"value\":[\"192.168.0.0/34\"]}]"),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
	}

	p := initRoutesTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/routes/{id}", p.GetRouteHandler).Methods("GET")
			router.HandleFunc("/api/routes/{id}", p.DeleteRouteHandler).Methods("DELETE")
			router.HandleFunc("/api/routes", p.CreateRouteHandler).Methods("POST")
			router.HandleFunc("/api/routes/{id}", p.UpdateRouteHandler).Methods("PUT")
			router.HandleFunc("/api/routes/{id}", p.PatchRouteHandler).Methods("PATCH")
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
