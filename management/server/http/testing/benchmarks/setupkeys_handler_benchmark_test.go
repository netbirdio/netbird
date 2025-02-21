//go:build api_benchmark
// +build api_benchmark

package benchmarks

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
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
)

// Map to store peers, groups, users, and setupKeys by name
var benchCasesSetupKeys = map[string]testing_tools.BenchmarkCase{
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
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - S":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - M":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - L":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Peers - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Groups - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Users - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - XL": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				requestBody := api.CreateSetupKeyRequest{
					AutoGroups: []string{testing_tools.TestGroupId},
					ExpiresIn:  testing_tools.ExpiresIn,
					Name:       testing_tools.NewKeyName + strconv.Itoa(i),
					Type:       "reusable",
					UsageLimit: 0,
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := testing_tools.BuildRequest(b, body, http.MethodPost, "/api/setup-keys", testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkUpdateSetupKey(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - S":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - M":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - L":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Peers - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Groups - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Users - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
		"Setup Keys - XL": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 3, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 7},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				groupId := testing_tools.TestGroupId
				if i%2 == 0 {
					groupId = testing_tools.NewGroupId
				}
				requestBody := api.SetupKeyRequest{
					AutoGroups: []string{groupId},
					Revoked:    false,
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := testing_tools.BuildRequest(b, body, http.MethodPut, "/api/setup-keys/"+testing_tools.TestKeyId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetOneSetupKey(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Setup Keys - S":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Setup Keys - M":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Setup Keys - L":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Peers - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Groups - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Users - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
		"Setup Keys - XL": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 3, MaxMsPerOpCICD: 5},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/setup-keys/"+testing_tools.TestKeyId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetAllSetupKeys(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 5},
		"Setup Keys - S":  {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4.5, MaxMsPerOpCICD: 6.5},
		"Setup Keys - M":  {MinMsPerOpLocal: 5, MaxMsPerOpLocal: 10, MinMsPerOpCICD: 11, MaxMsPerOpCICD: 14},
		"Setup Keys - L":  {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 55},
		"Peers - L":       {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 55},
		"Groups - L":      {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 55},
		"Users - L":       {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 55},
		"Setup Keys - XL": {MinMsPerOpLocal: 140, MaxMsPerOpLocal: 220, MinMsPerOpCICD: 150, MaxMsPerOpCICD: 220},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/setup-keys", testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkDeleteSetupKey(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Setup Keys - XS": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Setup Keys - S":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Setup Keys - M":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Setup Keys - L":  {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Peers - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Groups - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Users - L":       {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
		"Setup Keys - XL": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 6},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, 1000)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/setup-keys/"+"oldkey-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}
