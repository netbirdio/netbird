//go:build benchmark

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

	"github.com/prometheus/client_golang/prometheus/push"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const moduleUsers = "users"

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
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			recorder := httptest.NewRecorder()
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

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleUsers, testing_tools.OperationUpdate)
		})
	}
}

func BenchmarkGetOneUser(b *testing.B) {
	b.Skip("Skipping benchmark as endpoint is missing")

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			recorder := httptest.NewRecorder()
			b.ResetTimer()
			start := time.Now()
			req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/users/"+testing_tools.TestUserId, testing_tools.TestAdminId)
			for i := 0; i < b.N; i++ {
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleUsers, testing_tools.OperationGetOne)
		})
	}
}

func BenchmarkGetAllUsers(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			recorder := httptest.NewRecorder()
			b.ResetTimer()
			start := time.Now()
			req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/users", testing_tools.TestAdminId)
			for i := 0; i < b.N; i++ {
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleUsers, testing_tools.OperationGetAll)
		})
	}
}

func BenchmarkDeleteUsers(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for name, bc := range benchCasesUsers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/users.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, 1000, bc.SetupKeys)

			recorder := httptest.NewRecorder()
			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/users/"+"olduser-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleUsers, testing_tools.OperationDelete)
		})
	}
}

func TestMain(m *testing.M) {
	exitCode := m.Run()

	if exitCode == 0 && os.Getenv("CI") == "true" {
		runID := os.Getenv("GITHUB_RUN_ID")
		storeEngine := os.Getenv("NETBIRD_STORE_ENGINE")
		err := push.New("http://localhost:9091", "api_benchmark").
			Collector(testing_tools.BenchmarkDuration).
			Grouping("ci_run", runID).
			Grouping("store_engine", storeEngine).
			Push()
		if err != nil {
			log.Printf("Failed to push metrics: %v", err)
		} else {
			time.Sleep(1 * time.Minute)
			_ = push.New("http://localhost:9091", "api_benchmark").
				Grouping("ci_run", runID).
				Grouping("store_engine", storeEngine).
				Delete()
		}
	}

	os.Exit(exitCode)
}
