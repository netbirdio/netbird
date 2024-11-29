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

func BenchmarkCreateSetupKey(b *testing.B) {
	benchCases := []struct {
		name      string
		peers     int
		groups    int
		users     int
		setupKeys int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Setup Keys - XS", 10000, 10000, 10000, 5, 0.5, 2, 1, 12},
		{"Setup Keys - S", 5, 5, 5, 100, 0.5, 2, 1, 12},
		{"Setup Keys - M", 100, 20, 20, 1000, 0.5, 2, 1, 12},
		{"Setup Keys - L", 5, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Peers - L", 10000, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Groups - L", 5, 10000, 5, 5000, 0.5, 2, 1, 12},
		{"Users - L", 5, 5, 10000, 5000, 0.5, 2, 1, 12},
		{"Setup Keys - XL", 500, 50, 100, 25000, 0.5, 2, 1, 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.peers, bc.groups, bc.users, bc.setupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				requestBody := api.CreateSetupKeyRequest{
					AutoGroups: []string{"someGroupID"},
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

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > maxExpected {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkUpdateSetupKey(b *testing.B) {
	benchCases := []struct {
		name      string
		peers     int
		groups    int
		users     int
		setupKeys int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Setup Keys - XS", 10000, 10000, 10000, 5, 0.5, 3, 2, 15},
		{"Setup Keys - S", 5, 5, 5, 100, 0.5, 3, 3, 15},
		{"Setup Keys - M", 100, 20, 20, 1000, 0.5, 3, 3, 15},
		{"Setup Keys - L", 5, 5, 5, 5000, 0.5, 3, 3, 15},
		{"Peers - L", 10000, 5, 5, 5000, 0.5, 3, 3, 15},
		{"Groups - L", 5, 10000, 5, 5000, 0.5, 3, 3, 15},
		{"Users - L", 5, 5, 10000, 5000, 0.5, 3, 3, 15},
		{"Setup Keys - XL", 500, 50, 100, 25000, 0.5, 3, 3, 15},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.peers, bc.groups, bc.users, bc.setupKeys)

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

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > maxExpected {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkGetOneSetupKey(b *testing.B) {
	benchCases := []struct {
		name      string
		peers     int
		groups    int
		users     int
		setupKeys int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Setup Keys - XS", 10000, 10000, 10000, 5, 0.5, 2, 1, 12},
		{"Setup Keys - S", 5, 5, 5, 100, 0.5, 2, 1, 12},
		{"Setup Keys - M", 100, 20, 20, 1000, 0.5, 2, 1, 12},
		{"Setup Keys - L", 5, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Peers - L", 10000, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Groups - L", 5, 10000, 5, 5000, 0.5, 2, 1, 12},
		{"Users - L", 5, 5, 10000, 5000, 0.5, 2, 1, 12},
		{"Setup Keys - XL", 500, 50, 100, 25000, 0.5, 2, 1, 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.peers, bc.groups, bc.users, bc.setupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := buildRequest(b, nil, http.MethodGet, "/api/setup-keys/"+testKeyId, testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > maxExpected {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkGetAllSetupKeys(b *testing.B) {
	benchCases := []struct {
		name      string
		peers     int
		groups    int
		users     int
		setupKeys int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Setup Keys - XS", 10000, 10000, 10000, 5, 0.5, 2, 1, 10},
		{"Setup Keys - S", 5, 5, 5, 10, 0.5, 2, 1, 12},
		{"Setup Keys - M", 100, 20, 20, 1000, 5, 10, 5, 20},
		{"Setup Keys - L", 5, 5, 5, 5000, 30, 50, 50, 100},
		{"Peers - L", 10000, 5, 5, 5000, 30, 50, 50, 100},
		{"Groups - L", 5, 10000, 5, 5000, 30, 50, 50, 100},
		{"Users - L", 5, 5, 10000, 5000, 30, 50, 50, 100},
		{"Setup Keys - XL", 500, 50, 100, 25000, 140, 220, 300, 500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.peers, bc.groups, bc.users, bc.setupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				req := buildRequest(b, nil, http.MethodGet, "/api/setup-keys", testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > maxExpected {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkDeleteSetupKey(b *testing.B) {
	benchCases := []struct {
		name      string
		peers     int
		groups    int
		users     int
		setupKeys int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Setup Keys - XS", 10000, 10000, 10000, 5, 0.5, 2, 1, 12},
		{"Setup Keys - S", 5, 5, 5, 100, 0.5, 2, 1, 12},
		{"Setup Keys - M", 100, 20, 20, 1000, 0.5, 2, 1, 12},
		{"Setup Keys - L", 5, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Peers - L", 10000, 5, 5, 5000, 0.5, 2, 1, 12},
		{"Groups - L", 5, 10000, 5, 5000, 0.5, 2, 1, 12},
		{"Users - L", 5, 5, 10000, 5000, 0.5, 2, 1, 12},
		{"Setup Keys - XL", 500, 50, 100, 25000, 0.5, 2, 1, 12},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	recorder := httptest.NewRecorder()

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			apiHandler, am, _ := buildApiBlackBoxWithDBState(b, "testdata/setup_keys.sql", nil)
			populateTestData(b, am.(*server.DefaultAccountManager), bc.peers, bc.groups, bc.users, bc.setupKeys)

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				// depending on the test case we may fail do delete keys as no more keys are there
				req := buildRequest(b, nil, http.MethodGet, "/api/setup-keys/"+"oldkey-"+strconv.Itoa(i), testAdminId)
				apiHandler.ServeHTTP(recorder, req)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > maxExpected {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}
