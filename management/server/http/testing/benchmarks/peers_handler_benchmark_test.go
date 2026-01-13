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

const modulePeers = "peers"

// Map to store peers, groups, users, and setupKeys by name
var benchCasesPeers = map[string]testing_tools.BenchmarkCase{
	"Peers - XS":     {Peers: 5, Groups: 10000, Users: 10000, SetupKeys: 10000},
	"Peers - S":      {Peers: 100, Groups: 5, Users: 5, SetupKeys: 5},
	"Peers - M":      {Peers: 1000, Groups: 20, Users: 20, SetupKeys: 100},
	"Peers - L":      {Peers: 5000, Groups: 5, Users: 5, SetupKeys: 5},
	"Groups - L":     {Peers: 5000, Groups: 10000, Users: 5, SetupKeys: 5},
	"Users - L":      {Peers: 5000, Groups: 5, Users: 10000, SetupKeys: 5},
	"Setup Keys - L": {Peers: 5000, Groups: 5, Users: 5, SetupKeys: 10000},
	"Peers - XL":     {Peers: 25000, Groups: 50, Users: 100, SetupKeys: 500},
}

func BenchmarkUpdatePeer(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				requestBody := api.PeerRequest{
					Name: "peer" + strconv.Itoa(i),
				}

				// the time marshal will be recorded as well but for our use case that is ok
				body, err := json.Marshal(requestBody)
				assert.NoError(b, err)

				req := testing_tools.BuildRequest(b, body, http.MethodPut, "/api/peers/"+testing_tools.TestPeerId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, modulePeers, testing_tools.OperationUpdate)
		})
	}
}

func BenchmarkGetOnePeer(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/peers/"+testing_tools.TestPeerId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, modulePeers, testing_tools.OperationGetOne)
		})
	}
}

func BenchmarkGetAllPeers(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/peers", testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, modulePeers, testing_tools.OperationGetAll)
		})
	}
}

func BenchmarkDeletePeer(b *testing.B) {
	if os.Getenv("CI") != "true" {
		b.Skip("Skipping because CI is not set")
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), 1000, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/peers/"+"oldpeer-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateAPIBenchmarkResults(b, name, time.Since(start), recorder, modulePeers, testing_tools.OperationDelete)
		})
	}
}
