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
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Peers - XS":     {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 600, MinMsPerOpCICD: 600, MaxMsPerOpCICD: 3500},
		"Peers - S":      {MinMsPerOpLocal: 100, MaxMsPerOpLocal: 130, MinMsPerOpCICD: 80, MaxMsPerOpCICD: 200},
		"Peers - M":      {MinMsPerOpLocal: 130, MaxMsPerOpLocal: 150, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 300},
		"Peers - L":      {MinMsPerOpLocal: 230, MaxMsPerOpLocal: 270, MinMsPerOpCICD: 200, MaxMsPerOpCICD: 500},
		"Groups - L":     {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 600, MinMsPerOpCICD: 650, MaxMsPerOpCICD: 3500},
		"Users - L":      {MinMsPerOpLocal: 200, MaxMsPerOpLocal: 400, MinMsPerOpCICD: 250, MaxMsPerOpCICD: 600},
		"Setup Keys - L": {MinMsPerOpLocal: 200, MaxMsPerOpLocal: 400, MinMsPerOpCICD: 250, MaxMsPerOpCICD: 600},
		"Peers - XL":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 1000, MinMsPerOpCICD: 600, MaxMsPerOpCICD: 2000},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
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

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetOnePeer(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Peers - XS":     {MinMsPerOpLocal: 15, MaxMsPerOpLocal: 40, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 70},
		"Peers - S":      {MinMsPerOpLocal: 1, MaxMsPerOpLocal: 5, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 30},
		"Peers - M":      {MinMsPerOpLocal: 9, MaxMsPerOpLocal: 18, MinMsPerOpCICD: 15, MaxMsPerOpCICD: 50},
		"Peers - L":      {MinMsPerOpLocal: 40, MaxMsPerOpLocal: 90, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 130},
		"Groups - L":     {MinMsPerOpLocal: 80, MaxMsPerOpLocal: 130, MinMsPerOpCICD: 30, MaxMsPerOpCICD: 200},
		"Users - L":      {MinMsPerOpLocal: 40, MaxMsPerOpLocal: 90, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 130},
		"Setup Keys - L": {MinMsPerOpLocal: 40, MaxMsPerOpLocal: 90, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 130},
		"Peers - XL":     {MinMsPerOpLocal: 200, MaxMsPerOpLocal: 400, MinMsPerOpCICD: 200, MaxMsPerOpCICD: 750},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/peers/"+testing_tools.TestPeerId, testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkGetAllPeers(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Peers - XS":     {MinMsPerOpLocal: 40, MaxMsPerOpLocal: 70, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 150},
		"Peers - S":      {MinMsPerOpLocal: 2, MaxMsPerOpLocal: 10, MinMsPerOpCICD: 5, MaxMsPerOpCICD: 30},
		"Peers - M":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 20, MaxMsPerOpCICD: 70},
		"Peers - L":      {MinMsPerOpLocal: 110, MaxMsPerOpLocal: 150, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 300},
		"Groups - L":     {MinMsPerOpLocal: 150, MaxMsPerOpLocal: 200, MinMsPerOpCICD: 130, MaxMsPerOpCICD: 500},
		"Users - L":      {MinMsPerOpLocal: 100, MaxMsPerOpLocal: 170, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 400},
		"Setup Keys - L": {MinMsPerOpLocal: 100, MaxMsPerOpLocal: 170, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 400},
		"Peers - XL":     {MinMsPerOpLocal: 450, MaxMsPerOpLocal: 800, MinMsPerOpCICD: 500, MaxMsPerOpCICD: 1500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), bc.Peers, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodGet, "/api/peers", testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}

func BenchmarkDeletePeer(b *testing.B) {
	var expectedMetrics = map[string]testing_tools.PerformanceMetrics{
		"Peers - XS":     {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Peers - S":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Peers - M":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Peers - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Groups - L":     {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Users - L":      {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Setup Keys - L": {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
		"Peers - XL":     {MinMsPerOpLocal: 0, MaxMsPerOpLocal: 4, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 18},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for name, bc := range benchCasesPeers {
		b.Run(name, func(b *testing.B) {
			apiHandler, am, _ := testing_tools.BuildApiBlackBoxWithDBState(b, "../testdata/peers.sql", nil, false)
			testing_tools.PopulateTestData(b, am.(*server.DefaultAccountManager), 1000, bc.Groups, bc.Users, bc.SetupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := testing_tools.BuildRequest(b, nil, http.MethodDelete, "/api/peers/"+"oldpeer-"+strconv.Itoa(i), testing_tools.TestAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			testing_tools.EvaluateBenchmarkResults(b, name, time.Since(start), expectedMetrics[name], recorder)
		})
	}
}
