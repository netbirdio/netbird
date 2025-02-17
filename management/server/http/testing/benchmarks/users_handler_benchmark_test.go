//go:build benchmark
// +build benchmark

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
var benchCasesUsers = map[string]testing_tools.BenchmarkCase{
	"Users - XS":     {Peers: 10000, Groups: 10000, Users: 5, SetupKeys: 10000},
	"Users - S":      {Peers: 5, Groups: 5, Users: 10, SetupKeys: 5},
	"Users - M":      {Peers: 100, Groups: 20, Users: 1000, SetupKeys: 1000},
	"Users - L":      {Peers: 5, Groups: 5, Users: 5000, SetupKeys: 5},
	"Peers - L":      {Peers: 10000, Groups: 5, Users: 5000, SetupKeys: 5},
	"Groups - L":     {Peers: 5, Groups: 10000, Users: 5000, SetupKeys: 5},
	"Setup Keys - L": {Peers: 5, Groups: 5, Users: 5000, SetupKeys: 10000},
	"Users - XL":     {Peers: 500, Groups: 50, Users: 25000, SetupKeys: 3000},
}

func BenchmarkUpdateUser(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Users - XS":     {MinMsPerOpLocal: 700, MaxMsPerOpLocal: 1000, MinMsPerOpCICD: 1300, MaxMsPerOpCICD: 8000},
		"Users - S":      {MinMsPerOpLocal: 1, MaxMsPerOpLocal: 5, MinMsPerOpCICD: 4, MaxMsPerOpCICD: 50},
		"Users - M":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 40, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 250},
		"Users - L":      {MinMsPerOpLocal: 60, MaxMsPerOpLocal: 100, MinMsPerOpCICD: 90, MaxMsPerOpCICD: 700},
		"Peers - L":      {MinMsPerOpLocal: 300, MaxMsPerOpLocal: 500, MinMsPerOpCICD: 550, MaxMsPerOpCICD: 2400},
		"Groups - L":     {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 600, MinMsPerOpCICD: 750, MaxMsPerOpCICD: 5000},
		"Setup Keys - L": {MinMsPerOpLocal: 50, MaxMsPerOpLocal: 200, MinMsPerOpCICD: 130, MaxMsPerOpCICD: 1000},
		"Users - XL":     {MinMsPerOpLocal: 350, MaxMsPerOpLocal: 550, MinMsPerOpCICD: 650, MaxMsPerOpCICD: 3500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				groupId := testing_tools.TestGroupId
				if i%2 == 0 {
					groupId = testing_tools.NewGroupId
				}
				requestBody := api.UserRequest{
					AutoGroups: []string{groupId},
					IsBlocked:  false,
					Role:       "admin",
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := testing_tools.BuildRequest(b, body, http.MethodPut, "/api/users/"+testing_tools.TestUserId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetOneUser(b *testing.B) {
	b.Skip("Skipping benchmark as endpoint is missing")
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Users - XS":     {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - S":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - M":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Peers - L":      {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Groups - L":     {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Setup Keys - L": {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
		"Users - XL":     {MinMsPerOpLocal: 0.5, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 1, MaxMsPerOpCICD: 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/users/"+testing_tools.TestUserId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetAllUsers(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Users - XS":     {MinMsPerOpLocal: 50, MaxMsPerOpLocal: 90, MinMsPerOpCICD: 60, MaxMsPerOpCICD: 180},
		"Users - S":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 0, MaxMsPerOpCICD: 30},
		"Users - M":      {MinMsPerOpLocal: 5, MaxMsPerOpLocal: 12, MinMsPerOpCICD: 0, MaxMsPerOpCICD: 30},
		"Users - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 0, MaxMsPerOpCICD: 30},
		"Peers - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 0, MaxMsPerOpCICD: 30},
		"Groups - L":     {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 2, MinMsPerOpCICD: 0, MaxMsPerOpCICD: 30},
		"Setup Keys - L": {MinMsPerOpLocal: 40, MaxMsPerOpLocal: 140, MinMsPerOpCICD: 60, MaxMsPerOpCICD: 200},
		"Users - XL":     {MinMsPerOpLocal: 15, MaxMsPerOpLocal: 40, MinMsPerOpCICD: 20, MaxMsPerOpCICD: 90},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
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

func BenchmarkDeleteUsers(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Users - XS":     {MinMsPerOpLocal: 1000, MaxMsPerOpLocal: 1600, MinMsPerOpCICD: 1900, MaxMsPerOpCICD: 11000},
		"Users - S":      {MinMsPerOpLocal: 15, MaxMsPerOpLocal: 40, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 200},
		"Users - M":      {MinMsPerOpLocal: 15, MaxMsPerOpLocal: 70, MinMsPerOpCICD: 15, MaxMsPerOpCICD: 230},
		"Users - L":      {MinMsPerOpLocal: 15, MaxMsPerOpLocal: 45, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 190},
		"Peers - L":      {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 600, MinMsPerOpCICD: 650, MaxMsPerOpCICD: 1800},
		"Groups - L":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 800, MinMsPerOpCICD: 1200, MaxMsPerOpCICD: 7500},
		"Setup Keys - L": {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 200, MinMsPerOpCICD: 40, MaxMsPerOpCICD: 600},
		"Users - XL":     {MinMsPerOpLocal: 50, MaxMsPerOpLocal: 150, MinMsPerOpCICD: 80, MaxMsPerOpCICD: 400},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, 1000, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/users/"+"olduser-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}
