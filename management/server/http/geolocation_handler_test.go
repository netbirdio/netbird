package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/util"
)

func initGeolocationTestData(t *testing.T) *GeolocationsHandler {
	t.Helper()

	var (
		mmdbPath       = "../testdata/GeoLite2-City_20240305.mmdb"
		geonamesdbPath = "../testdata/geonames_20240305.db"
	)

	tempDir := t.TempDir()

	err := util.CopyFileContents(mmdbPath, path.Join(tempDir, filepath.Base(mmdbPath)))
	assert.NoError(t, err)

	err = util.CopyFileContents(geonamesdbPath, path.Join(tempDir, filepath.Base(geonamesdbPath)))
	assert.NoError(t, err)

	geo, err := geolocation.NewGeolocation(context.Background(), tempDir, false)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = geo.Stop() })

	return &GeolocationsHandler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFromTokenFunc: func(_ context.Context, claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				user := server.NewAdminUser("test_user")
				return &server.Account{
					Id: claims.AccountId,
					Users: map[string]*server.User{
						"test_user": user,
					},
				}, user, nil
			},
		},
		geolocationManager: geo,
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

func TestGetCitiesByCountry(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedCities []api.City
		requestType    string
		requestPath    string
	}{
		{
			name:           "Get cities with valid country iso code",
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedCities: []api.City{
				{
					CityName:  "Souni",
					GeonameId: 5819,
				},
				{
					CityName:  "Protaras",
					GeonameId: 18918,
				},
			},
			requestType: http.MethodGet,
			requestPath: "/api/locations/countries/CY/cities",
		},
		{
			name:           "Get cities with valid country iso code but zero cities",
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedCities: make([]api.City, 0),
			requestType:    http.MethodGet,
			requestPath:    "/api/locations/countries/DE/cities",
		},
		{
			name:           "Get cities with invalid country iso code",
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
			requestType:    http.MethodGet,
			requestPath:    "/api/locations/countries/12ds/cities",
		},
	}

	geolocationHandler := initGeolocationTestData(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)

			router := mux.NewRouter()
			router.HandleFunc("/api/locations/countries/{country}/cities", geolocationHandler.GetCitiesByCountry).Methods("GET")
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

			cities := make([]api.City, 0)
			if err = json.Unmarshal(content, &cities); err != nil {
				t.Fatalf("unmarshal request cities response : %v", err)
				return
			}
			assert.ElementsMatch(t, tc.expectedCities, cities)
		})
	}
}

func TestGetAllCountries(t *testing.T) {
	tt := []struct {
		name              string
		expectedStatus    int
		expectedBody      bool
		expectedCountries []api.Country
		requestType       string
		requestPath       string
	}{
		{
			name:           "Get all countries",
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedCountries: []api.Country{
				{
					CountryCode: "IR",
					CountryName: "Iran",
				},
				{
					CountryCode: "CY",
					CountryName: "Cyprus",
				},
				{
					CountryCode: "RW",
					CountryName: "Rwanda",
				},
				{
					CountryCode: "SO",
					CountryName: "Somalia",
				},
				{
					CountryCode: "YE",
					CountryName: "Yemen",
				},
				{
					CountryCode: "LY",
					CountryName: "Libya",
				},
				{
					CountryCode: "IQ",
					CountryName: "Iraq",
				},
			},
			requestType: http.MethodGet,
			requestPath: "/api/locations/countries",
		},
	}

	geolocationHandler := initGeolocationTestData(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)

			router := mux.NewRouter()
			router.HandleFunc("/api/locations/countries", geolocationHandler.GetAllCountries).Methods("GET")
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

			countries := make([]api.Country, 0)
			if err = json.Unmarshal(content, &countries); err != nil {
				t.Fatalf("unmarshal request cities response : %v", err)
				return
			}
			assert.ElementsMatch(t, tc.expectedCountries, countries)
		})
	}
}
