package proxy_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

type nopTransport struct{}

func (nopTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
	}, nil
}

func BenchmarkServeHTTP(b *testing.B) {
	rp := proxy.NewReverseProxy(nopTransport{}, "http", nil, nil)
	rp.AddMapping(proxy.Mapping{
		ID:        rand.Text(),
		AccountID: types.AccountID(rand.Text()),
		Host:      "app.example.com",
		Paths: map[string]*url.URL{
			"/": {
				Scheme: "http",
				Host:   "10.0.0.1:8080",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "203.0.113.50:12345"

	for b.Loop() {
		rp.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkServeHTTPHostCount(b *testing.B) {
	hostCounts := []int{1, 10, 100, 1_000, 10_000}

	for _, hostCount := range hostCounts {
		b.Run(fmt.Sprintf("hosts=%d", hostCount), func(b *testing.B) {
			rp := proxy.NewReverseProxy(nopTransport{}, "http", nil, nil)

			var target string
			targetIndex, err := rand.Int(rand.Reader, big.NewInt(int64(hostCount)))
			if err != nil {
				b.Fatal(err)
			}
			for i := range hostCount {
				id := rand.Text()
				host := fmt.Sprintf("%s.example.com", id)
				if int64(i) == targetIndex.Int64() {
					target = id
				}
				rp.AddMapping(proxy.Mapping{
					ID:        id,
					AccountID: types.AccountID(rand.Text()),
					Host:      host,
					Paths: map[string]*url.URL{
						"/": {
							Scheme: "http",
							Host:   "10.0.0.1:8080",
						},
					},
				})
			}

			req := httptest.NewRequest(http.MethodGet, "http://"+target+"/", nil)
			req.Host = target
			req.RemoteAddr = "203.0.113.50:12345"

			for b.Loop() {
				rp.ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
}

func BenchmarkServeHTTPPathCount(b *testing.B) {
	pathCounts := []int{1, 5, 10, 25, 50}

	for _, pathCount := range pathCounts {
		b.Run(fmt.Sprintf("paths=%d", pathCount), func(b *testing.B) {
			rp := proxy.NewReverseProxy(nopTransport{}, "http", nil, nil)

			var target string
			targetIndex, err := rand.Int(rand.Reader, big.NewInt(int64(pathCount)))
			if err != nil {
				b.Fatal(err)
			}

			paths := make(map[string]*url.URL, pathCount)
			for i := range pathCount {
				path := "/" + rand.Text()
				if int64(i) == targetIndex.Int64() {
					target = path
				}
				paths[path] = &url.URL{
					Scheme: "http",
					Host:   "10.0.0.1:" + fmt.Sprintf("%d", 8080+i),
				}
			}
			rp.AddMapping(proxy.Mapping{
				ID:        rand.Text(),
				AccountID: types.AccountID(rand.Text()),
				Host:      "app.example.com",
				Paths:     paths,
			})

			req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+target, nil)
			req.Host = "app.example.com"
			req.RemoteAddr = "203.0.113.50:12345"

			for b.Loop() {
				rp.ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
}
