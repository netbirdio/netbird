package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
)

// Map to store peers, groups, users, and setupKeys by name
var benchCasesSetupKeys = map[string]BenchmarkCase{
	"Setup Keys - XS": {Peers: 10000, Groups: 10000, Users: 10000, SetupKeys: 5},
	"Setup Keys - S":  {Peers: 5, Groups: 5, Users: 5, SetupKeys: 100},
	"Setup Keys - M":  {Peers: 100, Groups: 20, Users: 20, SetupKeys: 1000},
	"Setup Keys - L":  {Peers: 5, Groups: 5, Users: 5, SetupKeys: 5000},
	"Peers - L":       {Peers: 10000, Groups: 5, Users: 5, SetupKeys: 5000},
	"Groups - L":      {Peers: 5, Groups: 10000, Users: 5, SetupKeys: 5000},
	"Users - L":       {Peers: 5, Groups: 5, Users: 10000, SetupKeys: 5000},
	"Setup Keys - XL": {Peers: 500, Groups: 50, Users: 100, SetupKeys: 25000},
}

func BenchmarkCreateSetupKey(b *testing.B) {
	var expectedMetrics = map[string]PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - M":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - L":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Peers - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Groups - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - XL": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				requestBody := api.CreateSetupKeyRequest{
					AutoGroups: []string{testGroupId},
					ExpiresIn:  expiresIn,
					Name:       newKeyName + strconv.Itoa(i),
					Type:       "reusable",
					UsageLimit: 0,
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := buildRequest(b, body, http.MethodPost, "/api/setup-keys", testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			evaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkUpdateSetupKey(b *testing.B) {
	var expectedMetrics = map[string]PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Setup Keys - M":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Setup Keys - L":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Peers - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Groups - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Users - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
		"Setup Keys - XL": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 15},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				groupId := testGroupId
				if i%2 == 0 {
					groupId = newGroupId
				}
				requestBody := api.SetupKeyRequest{
					AutoGroups: []string{groupId},
					Revoked:    false,
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := buildRequest(b, body, http.MethodPut, "/api/setup-keys/"+testKeyId, testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			evaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetOneSetupKey(b *testing.B) {
	var expectedMetrics = map[string]PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - M":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - L":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Peers - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Groups - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - XL": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := buildRequest(b, nil, http.MethodGet, "/api/setup-keys/"+testKeyId, testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			evaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetAllSetupKeys(b *testing.B) {
	var expectedMetrics = map[string]PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 10},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - M":  {MinMsPerOpLocal: 5, MaxMsPerOpLocal: 10, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 30},
		"Setup Keys - L":  {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 150},
		"Peers - L":       {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 150},
		"Groups - L":      {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 150},
		"Users - L":       {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 150},
		"Setup Keys - XL": {MinMsPerOpLocal: 140, MaxMsPerOpLocal: 220, MinMsPerOpCICD: 250, MaxMsPerOpCICD: 500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := buildRequest(b, nil, http.MethodGet, "/api/setup-keys", testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			evaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkDeleteSetupKey(b *testing.B) {
	var expectedMetrics = map[string]PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - M":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - L":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Peers - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Groups - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - L":       {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - XL": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, 1000)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := buildRequest(b, nil, http.MethodDelete, "/api/setup-keys/"+"oldkey-"+strconv.Itoa(i), testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			evaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}
