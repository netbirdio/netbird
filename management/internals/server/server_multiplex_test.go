package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func newSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServeMultiplexedRoutesProtocols(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpListener.Close() })

	baseTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{newSelfSignedCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsListener := tls.NewListener(tcpListener, preferHTTP1ForDualProtoClients(baseTLSConfig))

	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, health.NewServer())
	t.Cleanup(grpcServer.Stop)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "proto=%d", r.ProtoMajor)
	})

	s := &BaseServer{errCh: make(chan error, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.serveMultiplexed(ctx, tlsListener, grpcServer, handler, true)

	addr := tcpListener.Addr().String()
	url := "https://" + addr + "/"

	grpcConn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = grpcConn.Close() })

	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()
	resp, err := healthpb.NewHealthClient(grpcConn).Check(checkCtx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)

	get := func(client *http.Client) string {
		t.Helper()
		res, err := client.Get(url)
		require.NoError(t, err)
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		_ = res.Body.Close()
		return string(body)
	}

	dualProtoClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	require.Equal(t, "proto=1", get(dualProtoClient), "dual-ALPN client should be steered to HTTP/1.1")

	h1OnlyClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
		},
	}
	require.Equal(t, "proto=1", get(h1OnlyClient))
}
