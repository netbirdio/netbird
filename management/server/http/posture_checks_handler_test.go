package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

var berlin = "Berlin"
var losAngeles = "Los Angeles"

func initPostureChecksTestData(postureChecks ...*posture.Checks) *PostureChecksHandler {
	testPostureChecks := make(map[string]*posture.Checks, len(postureChecks))
	for _, postureCheck := range postureChecks {
		testPostureChecks[postureCheck.ID] = postureCheck
	}

	return &PostureChecksHandler{
		accountManager: &mock_server.MockAccountManager{
			GetPostureChecksFunc: func(accountID, postureChecksID, userID string) (*posture.Checks, error) {
				p, ok := testPostureChecks[postureChecksID]
				if !ok {
					return nil, status.Errorf(status.NotFound, "posture checks not found")
				}
				return p, nil
			},
			SavePostureChecksFunc: func(accountID, userID string, postureChecks *posture.Checks) error {
				postureChecks.ID = "postureCheck"
				testPostureChecks[postureChecks.ID] = postureChecks
				return nil
			},
			DeletePostureChecksFunc: func(accountID, postureChecksID, userID string) error {
				_, ok := testPostureChecks[postureChecksID]
				if !ok {
					return status.Errorf(status.NotFound, "posture checks not found")
				}
				delete(testPostureChecks, postureChecksID)

				return nil
			},
			ListPostureChecksFunc: func(accountID, userID string) ([]*posture.Checks, error) {
				accountPostureChecks := make([]*posture.Checks, len(testPostureChecks))
				for _, p := range testPostureChecks {
					accountPostureChecks = append(accountPostureChecks, p)
				}
				return accountPostureChecks, nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				user := server.NewAdminUser("test_user")
				return &server.Account{
					Id: claims.AccountId,
					Users: map[string]*server.User{
						"test_user": user,
					},
					PostureChecks: postureChecks,
				}, user, nil
			},
		},
		geolocationManager: &geolocation.Geolocation{},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			}),
		),
	}
}

func TestGetPostureCheck(t *testing.T) {
	postureCheck := &posture.Checks{
		ID:   "postureCheck",
		Name: "nbVersion",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "1.0.0",
			},
		},
	}
	osPostureCheck := &posture.Checks{
		ID:   "osPostureCheck",
		Name: "osVersion",
		Checks: posture.ChecksDefinition{
			OSVersionCheck: &posture.OSVersionCheck{
				Linux: &posture.MinKernelVersionCheck{
					MinKernelVersion: "6.0.0",
				},
				Darwin: &posture.MinVersionCheck{
					MinVersion: "14",
				},
				Ios: &posture.MinVersionCheck{
					MinVersion: "",
				},
			},
		},
	}
	geoPostureCheck := &posture.Checks{
		ID:   "geoPostureCheck",
		Name: "geoLocation",
		Checks: posture.ChecksDefinition{
			GeoLocationCheck: &posture.GeoLocationCheck{
				Locations: []posture.Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: posture.CheckActionAllow,
			},
		},
	}
	privateNetworkCheck := &posture.Checks{
		ID:   "privateNetworkPostureCheck",
		Name: "privateNetwork",
		Checks: posture.ChecksDefinition{
			PeerNetworkRangeCheck: &posture.PeerNetworkRangeCheck{
				Ranges: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
				},
				Action: posture.CheckActionAllow,
			},
		},
	}

	tt := []struct {
		name           string
		id             string
		checkName      string
		expectedStatus int
		expectedBody   bool
		requestBody    io.Reader
	}{
		{
			name:           "GetPostureCheck NBVersion OK",
			expectedBody:   true,
			id:             postureCheck.ID,
			checkName:      postureCheck.Name,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetPostureCheck OSVersion OK",
			expectedBody:   true,
			id:             osPostureCheck.ID,
			checkName:      osPostureCheck.Name,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetPostureCheck GeoLocation OK",
			expectedBody:   true,
			id:             geoPostureCheck.ID,
			checkName:      geoPostureCheck.Name,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetPostureCheck PrivateNetwork OK",
			expectedBody:   true,
			id:             privateNetworkCheck.ID,
			checkName:      privateNetworkCheck.Name,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetPostureCheck Not Found",
			id:             "not-exists",
			expectedStatus: http.StatusNotFound,
		},
	}

	p := initPostureChecksTestData(postureCheck, osPostureCheck, geoPostureCheck, privateNetworkCheck)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/posture-checks/"+tc.id, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/posture-checks/{postureCheckId}", p.GetPostureCheck).Methods("GET")
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

			var got api.PostureCheck
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, got.Id, tc.id)
			assert.Equal(t, got.Name, tc.checkName)
		})
	}
}

func TestPostureCheckUpdate(t *testing.T) {
	str := func(s string) *string { return &s }
	tt := []struct {
		name                 string
		expectedStatus       int
		expectedBody         bool
		expectedPostureCheck *api.PostureCheck
		requestType          string
		requestPath          string
		requestBody          io.Reader
		setupHandlerFunc     func(handler *PostureChecksHandler)
	}{
		{
			name:        "Create Posture Checks NB version",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
                  "description": "default",
		           "checks": {
						"nb_version_check": {
							"min_version": "1.2.3"
		           		}
                  }
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str("default"),
				Checks: api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: "1.2.3",
					},
				},
			},
		},
		{
			name:        "Create Posture Checks NB version with No geolocation DB",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
                  "description": "default",
		           "checks": {
						"nb_version_check": {
							"min_version": "1.2.3"
		           		}
                  }
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str("default"),
				Checks: api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: "1.2.3",
					},
				},
			},
			setupHandlerFunc: func(handler *PostureChecksHandler) {
				handler.geolocationManager = nil
			},
		},
		{
			name:        "Create Posture Checks OS version",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
                  "description": "default",
		           "checks": {
						"os_version_check": {
							"android": {
								"min_version": "9.0.0"
							},
							"ios": {
								"min_version": "17.0"
							},
							"linux": {
								"min_kernel_version": "6.0.0"
							}
		           		}
                  }
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str("default"),
				Checks: api.Checks{
					OsVersionCheck: &api.OSVersionCheck{
						Android: &api.MinVersionCheck{
							MinVersion: "9.0.0",
						},
						Ios: &api.MinVersionCheck{
							MinVersion: "17.0",
						},
						Linux: &api.MinKernelVersionCheck{
							MinKernelVersion: "6.0.0",
						},
					},
				},
			},
		},
		{
			name:        "Create Posture Checks Geo Location",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
      				"name": "default",
                  	"description": "default",
					"checks": {
						"geo_location_check": {
							"locations": [
								{
									"city_name": "Berlin",
									"country_code": "DE"
								}
							],
							"action": "allow"
						}
					}
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str("default"),
				Checks: api.Checks{
					GeoLocationCheck: &api.GeoLocationCheck{
						Locations: []api.Location{
							{
								CityName:    &berlin,
								CountryCode: "DE",
							},
						},
						Action: api.GeoLocationCheckActionAllow,
					},
				},
			},
		},
		{
			name:        "Create Posture Checks Peer Network Range",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
					"description": "default",
					"checks": {
						"peer_network_range_check": {
							"action": "allow",
							"ranges": [
								"10.0.0.0/8"
							]
						}
					}
					}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str("default"),
				Checks: api.Checks{
					PeerNetworkRangeCheck: &api.PeerNetworkRangeCheck{
						Ranges: []string{
							"10.0.0.0/8",
						},
						Action: api.PeerNetworkRangeCheckActionAllow,
					},
				},
			},
		},
		{
			name:        "Create Posture Checks Geo Location with No geolocation DB",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
      				"name": "default",
                  	"description": "default",
					"checks": {
						"geo_location_check": {
							"locations": [
								{
									"city_name": "Berlin",
									"country_code": "DE"
								}
							],
							"action": "allow"
						}
					}
				}`)),
			expectedStatus: http.StatusPreconditionFailed,
			expectedBody:   false,
			setupHandlerFunc: func(handler *PostureChecksHandler) {
				handler.geolocationManager = nil
			},
		},
		{
			name:        "Create Posture Checks Invalid Check",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                   "name": "default",
                   "checks": {
						"non_existing_check": {
							"min_version": "1.2.0"
                   	}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Create Posture Checks Invalid Name",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                   "checks": {
						"nb_version_check": {
							"min_version": "1.2.0"
                   	}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Create Posture Checks Invalid NetBird's Min Version",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
                   "checks": {
						"nb_version_check": {}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Create Posture Checks Invalid Geo Location",
			requestType: http.MethodPost,
			requestPath: "/api/posture-checks",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
                   "checks": {
						"geo_location_check": {}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Update Posture Checks NB Version",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/postureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
		           "checks": {
						"nb_version_check": {
							"min_version": "1.9.0"
		           		}
					}
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str(""),
				Checks: api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: "1.9.0",
					},
				},
			},
		},
		{
			name:        "Update Posture Checks OS Version",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/osPostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
		           "checks": {
						"os_version_check": {
							"linux": {
								"min_kernel_version": "6.9.0"
							}
		           		}
					}
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str(""),
				Checks: api.Checks{
					OsVersionCheck: &api.OSVersionCheck{
						Linux: &api.MinKernelVersionCheck{
							MinKernelVersion: "6.9.0",
						},
					},
				},
			},
		},
		{
			name:        "Update Posture Checks OS Version with No geolocation DB",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/osPostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
		           "name": "default",
		           "checks": {
						"os_version_check": {
							"linux": {
								"min_kernel_version": "6.9.0"
							}
		           		}
					}
				}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str(""),
				Checks: api.Checks{
					OsVersionCheck: &api.OSVersionCheck{
						Linux: &api.MinKernelVersionCheck{
							MinKernelVersion: "6.9.0",
						},
					},
				},
			},
			setupHandlerFunc: func(handler *PostureChecksHandler) {
				handler.geolocationManager = nil
			},
		},
		{
			name:        "Update Posture Checks Geo Location",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/geoPostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
					"checks": {
						"geo_location_check": {
							"locations": [
								{
									"city_name": "Los Angeles",
									"country_code": "US"
								}
							],
							"action": "allow"
						}
					}
					}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str(""),
				Checks: api.Checks{
					GeoLocationCheck: &api.GeoLocationCheck{
						Locations: []api.Location{
							{
								CityName:    &losAngeles,
								CountryCode: "US",
							},
						},
						Action: api.GeoLocationCheckActionAllow,
					},
				},
			},
		},
		{
			name:        "Update Posture Checks Geo Location with No geolocation DB",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/geoPostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
					"checks": {
						"geo_location_check": {
							"locations": [
								{
									"city_name": "Los Angeles",
									"country_code": "US"
								}
							],
							"action": "allow"
						}
					}
					}`)),
			expectedStatus: http.StatusPreconditionFailed,
			expectedBody:   false,
			setupHandlerFunc: func(handler *PostureChecksHandler) {
				handler.geolocationManager = nil
			},
		},
		{
			name:        "Update Posture Checks Geo Location with not valid action",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/geoPostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
					"checks": {
						"geo_location_check": {
							"locations": [
								{
									"city_name": "Los Angeles",
									"country_code": "US"
								}
							],
							"action": "not-valid"
						}
					}
					}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
			setupHandlerFunc: func(handler *PostureChecksHandler) {
				handler.geolocationManager = nil
			},
		},
		{
			name:        "Update Posture Checks Invalid Check",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/postureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                   "name": "default",
                   "checks": {
						"non_existing_check": {
							"min_version": "1.2.0"
                   	}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Update Posture Checks Invalid Name",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/postureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
                   "checks": {
						"nb_version_check": {
							"min_version": "1.2.0"
                   	}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Update Posture Checks Invalid NetBird's Min Version",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/postureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
                   "checks": {
						"nb_version_check": {}
					}
				}`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Update Posture Checks Peer Network Range",
			requestType: http.MethodPut,
			requestPath: "/api/posture-checks/peerNetworkRangePostureCheck",
			requestBody: bytes.NewBuffer(
				[]byte(`{
					"name": "default",
					"checks": {
						"peer_network_range_check": {
							"action": "deny",
							"ranges": [
								"192.168.1.0/24"
							]
						}
					}
					}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedPostureCheck: &api.PostureCheck{
				Id:          "postureCheck",
				Name:        "default",
				Description: str(""),
				Checks: api.Checks{
					PeerNetworkRangeCheck: &api.PeerNetworkRangeCheck{
						Ranges: []string{
							"192.168.1.0/24",
						},
						Action: api.PeerNetworkRangeCheckActionDeny,
					},
				},
			},
		},
	}

	p := initPostureChecksTestData(&posture.Checks{
		ID:   "postureCheck",
		Name: "postureCheck",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "1.0.0",
			},
		},
	},
		&posture.Checks{
			ID:   "osPostureCheck",
			Name: "osPostureCheck",
			Checks: posture.ChecksDefinition{
				OSVersionCheck: &posture.OSVersionCheck{
					Linux: &posture.MinKernelVersionCheck{
						MinKernelVersion: "5.0.0",
					},
				},
			},
		},
		&posture.Checks{
			ID:   "geoPostureCheck",
			Name: "geoLocation",
			Checks: posture.ChecksDefinition{
				GeoLocationCheck: &posture.GeoLocationCheck{
					Locations: []posture.Location{
						{
							CountryCode: "DE",
							CityName:    "Berlin",
						},
					},
					Action: posture.CheckActionDeny,
				},
			},
		},
		&posture.Checks{
			ID:   "peerNetworkRangePostureCheck",
			Name: "peerNetworkRange",
			Checks: posture.ChecksDefinition{
				PeerNetworkRangeCheck: &posture.PeerNetworkRangeCheck{
					Ranges: []netip.Prefix{
						netip.MustParsePrefix("192.168.0.0/24"),
					},
					Action: posture.CheckActionAllow,
				},
			},
		},
	)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			defaultHandler := *p
			if tc.setupHandlerFunc != nil {
				tc.setupHandlerFunc(&defaultHandler)
			}

			router := mux.NewRouter()
			router.HandleFunc("/api/posture-checks", defaultHandler.CreatePostureCheck).Methods("POST")
			router.HandleFunc("/api/posture-checks/{postureCheckId}", defaultHandler.UpdatePostureCheck).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
				return
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			if !tc.expectedBody {
				return
			}

			expected, err := json.Marshal(tc.expectedPostureCheck)
			if err != nil {
				t.Fatalf("marshal expected posture check: %v", err)
				return
			}

			assert.Equal(t, strings.Trim(string(content), " \n"), string(expected), "content mismatch")
		})
	}
}

func TestPostureCheck_validatePostureChecksUpdate(t *testing.T) {
	// empty name
	err := validatePostureChecksUpdate(api.PostureCheckUpdate{})
	assert.Error(t, err)

	// empty checks
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default"})
	assert.Error(t, err)
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{}})
	assert.Error(t, err)

	// not valid NbVersionCheck
	nbVersionCheck := api.NBVersionCheck{}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{NbVersionCheck: &nbVersionCheck}})
	assert.Error(t, err)

	// valid NbVersionCheck
	nbVersionCheck = api.NBVersionCheck{MinVersion: "1.0"}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{NbVersionCheck: &nbVersionCheck}})
	assert.NoError(t, err)

	// not valid OsVersionCheck
	osVersionCheck := api.OSVersionCheck{}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{OsVersionCheck: &osVersionCheck}})
	assert.Error(t, err)

	// not valid OsVersionCheck
	osVersionCheck = api.OSVersionCheck{Linux: &api.MinKernelVersionCheck{}}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{OsVersionCheck: &osVersionCheck}})
	assert.Error(t, err)

	// not valid OsVersionCheck
	osVersionCheck = api.OSVersionCheck{Linux: &api.MinKernelVersionCheck{}, Darwin: &api.MinVersionCheck{MinVersion: "14.2"}}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{OsVersionCheck: &osVersionCheck}})
	assert.Error(t, err)

	// valid OsVersionCheck
	osVersionCheck = api.OSVersionCheck{Linux: &api.MinKernelVersionCheck{MinKernelVersion: "6.0"}}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{OsVersionCheck: &osVersionCheck}})
	assert.NoError(t, err)

	// valid OsVersionCheck
	osVersionCheck = api.OSVersionCheck{
		Linux:  &api.MinKernelVersionCheck{MinKernelVersion: "6.0"},
		Darwin: &api.MinVersionCheck{MinVersion: "14.2"},
	}
	err = validatePostureChecksUpdate(api.PostureCheckUpdate{Name: "Default", Checks: &api.Checks{OsVersionCheck: &osVersionCheck}})
	assert.NoError(t, err)

	// valid peer network range check
	peerNetworkRangeCheck := api.PeerNetworkRangeCheck{
		Action: api.PeerNetworkRangeCheckActionAllow,
		Ranges: []string{
			"192.168.1.0/24", "10.0.0.0/8",
		},
	}
	err = validatePostureChecksUpdate(
		api.PostureCheckUpdate{
			Name: "Default",
			Checks: &api.Checks{
				PeerNetworkRangeCheck: &peerNetworkRangeCheck,
			},
		},
	)
	assert.NoError(t, err)

	// invalid peer network range check
	peerNetworkRangeCheck = api.PeerNetworkRangeCheck{
		Action: api.PeerNetworkRangeCheckActionDeny,
		Ranges: []string{},
	}
	err = validatePostureChecksUpdate(
		api.PostureCheckUpdate{
			Name: "Default",
			Checks: &api.Checks{
				PeerNetworkRangeCheck: &peerNetworkRangeCheck,
			},
		},
	)
	assert.Error(t, err)

	// invalid peer network range check
	peerNetworkRangeCheck = api.PeerNetworkRangeCheck{
		Action: "unknownAction",
		Ranges: []string{},
	}
	err = validatePostureChecksUpdate(
		api.PostureCheckUpdate{
			Name: "Default",
			Checks: &api.Checks{
				PeerNetworkRangeCheck: &peerNetworkRangeCheck,
			},
		},
	)
	assert.Error(t, err)
}
