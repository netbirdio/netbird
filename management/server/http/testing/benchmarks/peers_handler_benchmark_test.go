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
		"Peers - XS":     {MinMsPerOpLocal: 1300, MaxMsPerOpLocal: 1700, MinMsPerOpCICD: 2200, MaxMsPerOpCICD: 2800},
		"Peers - S":      {MinMsPerOpLocal: 100, MaxMsPerOpLocal: 130, MinMsPerOpCICD: 80, MaxMsPerOpCICD: 140},
		"Peers - M":      {MinMsPerOpLocal: 160, MaxMsPerOpLocal: 190, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 300},
		"Peers - L":      {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 430, MinMsPerOpCICD: 450, MaxMsPerOpCICD: 750},
		"Groups - L":     {MinMsPerOpLocal: 1200, MaxMsPerOpLocal: 1500, MinMsPerOpCICD: 1900, MaxMsPerOpCICD: 2500},
		"Users - L":      {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 800, MinMsPerOpCICD: 800, MaxMsPerOpCICD: 1200},
		"Setup Keys - L": {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 700, MinMsPerOpCICD: 600, MaxMsPerOpCICD: 1000},
		"Peers - XL":     {MinMsPerOpLocal: 1400, MaxMsPerOpLocal: 1900, MinMsPerOpCICD: 2200, MaxMsPerOpCICD: 2800},
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
		"Peers - XS":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 900, MinMsPerOpCICD: 1100, MaxMsPerOpCICD: 1500},
		"Peers - S":      {MinMsPerOpLocal: 3, MaxMsPerOpLocal: 7, MinMsPerOpCICD: 2, MaxMsPerOpCICD: 12},
		"Peers - M":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 40, MinMsPerOpCICD: 35, MaxMsPerOpCICD: 65},
		"Peers - L":      {MinMsPerOpLocal: 120, MaxMsPerOpLocal: 160, MinMsPerOpCICD: 100, MaxMsPerOpCICD: 300},
		"Groups - L":     {MinMsPerOpLocal: 500, MaxMsPerOpLocal: 750, MinMsPerOpCICD: 900, MaxMsPerOpCICD: 1300},
		"Users - L":      {MinMsPerOpLocal: 200, MaxMsPerOpLocal: 300, MinMsPerOpCICD: 300, MaxMsPerOpCICD: 550},
		"Setup Keys - L": {MinMsPerOpLocal: 200, MaxMsPerOpLocal: 300, MinMsPerOpCICD: 300, MaxMsPerOpCICD: 550},
		"Peers - XL":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 800, MinMsPerOpCICD: 900, MaxMsPerOpCICD: 1300},
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
		"Peers - XS":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 900, MinMsPerOpCICD: 1100, MaxMsPerOpCICD: 1500},
		"Peers - S":      {MinMsPerOpLocal: 4, MaxMsPerOpLocal: 10, MinMsPerOpCICD: 15, MaxMsPerOpCICD: 21},
		"Peers - M":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 40, MaxMsPerOpCICD: 60},
		"Peers - L":      {MinMsPerOpLocal: 130, MaxMsPerOpLocal: 170, MinMsPerOpCICD: 200, MaxMsPerOpCICD: 300},
		"Groups - L":     {MinMsPerOpLocal: 5000, MaxMsPerOpLocal: 5500, MinMsPerOpCICD: 7000, MaxMsPerOpCICD: 11000},
		"Users - L":      {MinMsPerOpLocal: 250, MaxMsPerOpLocal: 300, MinMsPerOpCICD: 300, MaxMsPerOpCICD: 600},
		"Setup Keys - L": {MinMsPerOpLocal: 250, MaxMsPerOpLocal: 350, MinMsPerOpCICD: 300, MaxMsPerOpCICD: 600},
		"Peers - XL":     {MinMsPerOpLocal: 900, MaxMsPerOpLocal: 1300, MinMsPerOpCICD: 1300, MaxMsPerOpCICD: 1900},
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
		"Peers - XS":     {MinMsPerOpLocal: 600, MaxMsPerOpLocal: 800, MinMsPerOpCICD: 1100, MaxMsPerOpCICD: 1300},
		"Peers - S":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 70},
		"Peers - M":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 70},
		"Peers - L":      {MinMsPerOpLocal: 20, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 50, MaxMsPerOpCICD: 70},
		"Groups - L":     {MinMsPerOpLocal: 400, MaxMsPerOpLocal: 550, MinMsPerOpCICD: 700, MaxMsPerOpCICD: 900},
		"Users - L":      {MinMsPerOpLocal: 170, MaxMsPerOpLocal: 210, MinMsPerOpCICD: 290, MaxMsPerOpCICD: 350},
		"Setup Keys - L": {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 125, MinMsPerOpCICD: 160, MaxMsPerOpCICD: 200},
		"Peers - XL":     {MinMsPerOpLocal: 30, MaxMsPerOpLocal: 50, MinMsPerOpCICD: 60, MaxMsPerOpCICD: 80},
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
