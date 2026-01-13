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

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
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

const moduleSetupKeys = "setup_keys"

func BenchmarkCreateSetupKey(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
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

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleSetupKeys, testing_tools.OperationCreate)
		})
	}
}

func BenchmarkUpdateSetupKey(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
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

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleSetupKeys, testing_tools.OperationUpdate)
		})
	}
}

func BenchmarkGetOneSetupKey(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/setup-keys/"+testing_tools.TestKeyId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleSetupKeys, testing_tools.OperationGetOne)
		})
	}
}

func BenchmarkGetAllSetupKeys(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/setup-keys", testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleSetupKeys, testing_tools.OperationGetAll)
		})
	}
}

func BenchmarkDeleteSetupKey(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesSetupKeys {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/setup_keys.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, 1000)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/setup-keys/"+"oldkey-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, moduleSetupKeys, testing_tools.OperationDelete)
		})
	}
}
